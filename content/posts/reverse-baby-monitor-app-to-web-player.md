---
title: "把一款婴幼儿看护 App 的直播搬到浏览器"
subtitle: "静态分析、native 算法还原、流量中间人、实时转码"
date: 2026-10-06T23:30:00+08:00
draft: false
categories:
  - 逆向工程
  - 音视频
tags:
  - Android
  - iOS
  - Reverse Engineering
  - radare2
  - ELF
  - AES
  - MITM
  - FFmpeg
summary: "一款只能在自家 App 里看画面的婴幼儿看护器，最终在浏览器里播了起来。记录整条链路上的判断依据，以及只有接上真机才暴露出来的问题。"
---

起因是家里添了宝宝，买了个婴幼儿看护器。画面挺清楚，问题是只能在厂商那个 App 里看：没有网页端，也不能投屏，家人想看还得下载登录。于是想把它搬到浏览器里。

这篇记的是整个过程，包括几次判断错误的地方。对的部分通常没什么可写的，错的地方才有。

> 边界声明：涉及的目标设备为本人购买并拥有管理权限的硬件，分析均在本人设备与本人账号上进行，目的是家庭局域网内自用。文中厂商域名、密钥、Token、设备标识等已全部脱敏。

---

## 一、先打开 zip 看看

拿到 APK 别急着反编译。把它当 zip 打开，看一眼 `lib/` 下面有什么，后面怎么打基本就定了。

```python
import zipfile, collections
z = zipfile.ZipFile('target.apk')
print(collections.Counter(n.split('/')[0] for n in z.namelist()))
for n in z.namelist():
    if n.endswith('.so'):
        print(n, z.getinfo(n).file_size)
```

`lib/arm64-v8a/` 里躺着 `libTUTKGlobalAPIs.so`、`libAVAPIs.so` 这类第三方库，名字被改过的也能从残留字符串认出来。看到这组名字就知道：**TUTK Kalay + 腾讯云 IoT Video（XP2P）** 两套 P2P 方案。

然后 grep `rtsp://` 和 `onvif`，零结果：不存在拼一条 RTSP 地址让 VLC 直接打开的捷径，P2P 是唯一入口。

好消息是，这两家都公开了 Windows / Linux 版 SDK。拉流不用自己去啃协议，只要拿到 SDK 需要的那几个参数就行。整件事的难度一下子从「逆向一套音视频协议」降到了「搞到几个字符串」。

## 二、播放链路

jadx 反编译：

```bash
jadx -d out --threads-count 6 target.apk
```

从 App 层往下追，链路不长：

```
某个 Activity
  └─ TencentIOT.startService(productId, deviceName, xp2pInfo)
      └─ XP2P.startService(id, productId, deviceName, xp2pInfo, config)   ← native
          ├─ 注册回调，等 ready 事件
          └─ delegateHttpFlv(id) → 拿到本机代理地址
              └─ GET {proxy}/ipc.flv?action=live&channel=0&quality=high
```

核心是三个参数：`productId`、`deviceName`、`xp2pInfo`。顺着 `deviceName` 往上追，它来自一个云端接口；再往上，每个请求的 Header 里带着 `token` 和 `secret`（userId）。

链路弄清楚了：那几个参数厂商云端本来就有，App 也是联网取的，照着它的请求打过去就行。唯一的问题是，请求包是加密的。

## 三、还原 postBody

所有业务请求都是一个形式：

```
POST https://<厂商域名>/<业务路径>
Body: data=<一坨 base64>
```

`data` 是 native 层算出来的。用 radare2 打开对应的 `.so`：

```bash
radare2 -q -a arm -b 64 -c "is~+Java" libXXX.so
```

JNI 导出函数一般只有几十行，基本就是层包装。真正的实现在内部符号里，中间靠间接调用绕过去。这里踩了第一个坑：反汇编出现 `blr xN`，`xN` 寄存器的值来自某个 GOT 槽，而 radare2 没显示目标符号：它没有做重定位求解。

自己写个小解析器解决，不到 60 行：

```python
# 遍历 .rela.dyn / .rela.plt，建立 got_addr -> symbol_name 映射
def relocs(self):
    for sec in self.sections:
        if sec['type'] not in (SHT_RELA, SHT_REL):
            continue
        # 逐条读 r_offset / r_info，用 dynsym 把符号索引换成名字
        ...
```

查到那个 GOT 槽绑定的符号名，再从符号表算出实现地址，反汇编过去，算法骨架就出来了：

```
A    = "参数串&reqType=<n>&timestamp=<unix秒>"
sign = md5(A + SALT).hexdigest().lower()
B    = A + "&sign=" + sign
data = base64( base64( AES-128-CBC(B) ) )     ← 注意是两层
```

key、IV、SALT 三个常量在 `.rodata` 里明文躺着。

提取常量时踩了个小坑：字符串地址靠 `adrp + add` 拼，第一次忘了加页内偏移，dump 出来全是乱码。

```
adrp  x0, 0x34000      ; 页基址
add   x0, x0, 0xa9e    ; 页内偏移 → 实际 0x34a9e
```

ARM64 上别把 `adrp` 的立即数直接当地址用。

## 四、让服务器判断单层还是双层

静态看那两条相似的 base64 指令很容易看漏。与其反复读汇编，不如打两个请求过去看它怎么回：

```python
for double in (True, False):
    body = make_body(params, double_b64=double)
    print(double, post(endpoint, {'data': body}))
```

结果如下：

| 发送的内容 | 服务器返回 |
|---|---|
| **双层** base64 | `{"is_success":500713,"msg":"TOKEN expired"}` |
| 单层 base64 | `{"is_success":500102,"msg":"not fit the rule"}` |

双层时服务器解开密文一路处理到了鉴权环节，只是嫌 token 无效（我们当然没有真 token）；单层时它连第一步都没过。

再打一次登录，返回「该账号暂未注册」。加密协议这块可以确认没问题了。

顺带确认密码是明文进包的（App 侧只校验几个特殊字符），网页端直接传原文。

## 五、AES 加解密对齐

算法骨架确定是 AES-128-CBC。动手接入业务前，先用官方标准测试向量验证加解密逻辑的准确性：

```python
# FIPS-197 附录 C.1 + NIST SP 800-38A F.2.5 CBC 向量
key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
iv  = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
assert aes_cbc_decrypt(ct, key, iv) == expected_plaintext
```

加解密双向对齐之后，才能继续写上层的业务调用。

## 六、「检测到您在新设备进行登录」

在自己电脑上拿账号密码登录，服务器回了这么一句。

去资源文件里 grep 这句话本身，找到出处 `auth_tips`，全文是「检测到您在新设备进行登录，需通过手机短信验证您的身份，验证码将发送至……」。

这不是报错，是流程中间的一步。对应的 Activity 会弹验证码框，填完再登录一次。

顺着登录参数往下挖，有个字段叫 `uniqueDevice`，值是 Android 的 ANDROID_ID。grep 整个代码库，**这个字段只被登录接口用过一次**。

服务端判断是不是新设备，从头到尾只看这一个字符串。而手机早就登录过了，它的 ID 早在白名单里。把那个 ID 拿来用，服务器就会认为这台电脑是那台手机。

## 七、从 HTTPS 流量直接截取设备 ID 与登录凭证

在 Android 上，可以直接通过 `adb shell settings get secure android_id` 获取设备 ID，而 iPhone 没有这样的机制，于是直接走 HTTPS 劫持。

手机上的 App 每次发请求都会带上合法的 `uniqueDevice`、`token` 和 `secret`，直接解开流量就能把设备校验和登录凭证全拿到，连账号密码登录都省了。

动手前先确认目标 App 有没有做 SSL Pinning。如果做了，中间人证书在握手阶段就会被信任链拒掉。

Android 侧的配置在 `res/xml/network_security_config.xml`：

```xml
<network-security-config>
    <base-config cleartextTrafficPermitted="true" />
</network-security-config>
```

只有明文放行，没有任何 `<pin-set>`，iOS 端通常也是同样策略。

方案就此确定：让 iPhone 的流量临时经过电脑代理，直接截获并解密请求包中的凭证。

## 八、证书与中间人代理

要拦截 iPhone 的 HTTPS 流量，核心是两件事：给手机安装并信任自定义根 CA，以及起一个 TLS 中间人代理服务动态签发目标域名的证书。

### X.509 证书规范的几个坑

签发伪造证书给 iOS 客户端用，握手时有几个细节需要注意：

| 坑 | 现象 | 原因 / 处理 |
|---|---|---|
| 缺 SKI / AKI | 客户端拒绝握手 | 证书扩展中必须包含 `subjectKeyIdentifier` 与 `authorityKeyIdentifier` |
| AKI 值多包一层 OCTET STRING | 客户端解析乱码 | 证书的 `extnValue` 本身已经是 OCTET STRING，内层不用重复包装 |
| 缺 SAN 扩展 | 证书校验不通过 | 必须在 Subject Alternative Name 中准确匹配目标厂商域名 |

配置妥当后，双向交叉验证：

```bash
# 校验签发的域名证书
openssl verify -CAfile ca.crt -purpose sslserver leaf.crt   # → OK
```

```python
# 起 TLS 服务，客户端只信任这个 CA 并做主机名校验
ctx = ssl.create_default_context(cafile="ca.crt")
ctx.wrap_socket(sock, server_hostname="target.example.com")
# → TLSv1.3 / TLS_AES_256_GCM_SHA384 / SAN 通过
```

### 代理服务与证书下发

手机配置 Wi-Fi 代理后，HTTP 请求行会变成绝对 URI（`GET http://<IP>:<PORT>/ HTTP/1.1`），代理服务需要将请求路径归一化并进行分流：请求代理自身时提供 CA 证书下载与引导页；目标业务请求进行 TLS 劫持解密；其他外网流量直接建立隧道透传。

```python
class Proxy(BaseHTTPRequestHandler):
    def _target(self):
        """绝对 URI 与相对路径归一化，还原为 (host, port, path)"""
        if self.path.startswith(("http://", "https://")):
            u = urllib.parse.urlsplit(self.path)
            port = u.port or (443 if u.scheme == "https" else 80)
            return u.hostname or "", port, (u.path or "/") + (("?" + u.query) if u.query else "")
        host = (self.headers.get("Host") or "").split(":")[0]
        port = LISTEN_PORT
        return host, port, self.path

    def _is_self(self, host, port):
        """判断是否请求代理服务自身，避免回环死循环"""
        return port == LISTEN_PORT and host in all_local_ips()

    def do_GET(self):
        host, port, path = self._target()
        if self._is_self(host, port):
            # 提供根证书下载与引导页，同时兼容 iOS 的网络探测请求
            return self._serve_local(path)
        self._forward_http(host, port)
```

手机连接代理后，访问本地代理服务下载并信任根 CA，之后启动 App 即可顺利捕获目标流量。

## 九、真机实测

抓到真实 `token` 和 `secret` 之后立刻就能调 API 了，但之前自测没暴露出来的问题也全冒了出来。

### deviceName 用错字段

云端返回的设备对象里同时有两个「设备名」：

```json
{
  "deviceName": "某某二代看护器",
  "p2pDeviceName": "00000000_000000_00",
  "productId": "XXXXXXXXXX"
}
```

我理所当然取了前者。对比实验的结果：

| 传的值 | 服务器返回 |
|---|---|
| `某某二代看护器` | `is_success: 0`，「请勿重复验证签名」 |
| `<真实 P2P 序列号>` | `is_success: 1`，正常拿到 `xp2pInfo` |

铁证是 App 里的一行 `stopService(productId + "/" + p2pDeviceName)`。调用点比字段命名可靠得多。

### 三层嵌套的 JSON 字符串

`getScP2pInfo` 的返回是俄罗斯套娃，而且每一层都是字符串不是对象：

```
{"is_success":1, "data": "<字符串>"}
  {"Data": "<字符串>"}
    {"_sys_xp2p_info": {"Value": "XP2P0m..."}}
```

直接 `.get()` 当场 `AttributeError`。写了个递归慢慢剥，不再假设层级：

```python
def extract_xp2p_info(resp, depth=0):
    """遇到 dict/list 往里走，遇到 JSON 字符串就 json.loads"""
    if depth > 6:
        return None
    if isinstance(resp, str):
        try:
            return extract_xp2p_info(json.loads(resp), depth + 1)
        except Exception:
            return None
    ...
```

假数据永远编不出「同一个东西两个字段、一个昵称一个真 ID」这种意外。

## 十、P2P 通了，画面一直转圈

日志显示 P2P 建连成功，也顺利拿到了本机代理地址：

```
startService(...) rc=0
[XP2P] event=1004 {"mode":"ready"}
本机代理: http://127.0.0.1:60097/<SDK代理路径>
```

代理能正常读到 FLV 数据流，`FLV` 魔数也正确，但浏览器里就是一直转圈。

一番排查后发现：**flv.js 和 Chrome 的 MSE 原生都解不了 FLV 容器里的 H.265**。

把读到的 FLV tag 头解析出来看一眼编码格式：

```python
# FLV video tag 首字节低 4 位是 CodecID
if ttype == 9:
    codec = body[0] & 0x0f   # 7 = H.264/AVC, 12 = H.265/HEVC
```

```
videocodecid = 12  →  H.265 / HEVC    1920x1080 @ 20fps
audiocodecid = 10  →  AAC 16kHz
```

摄像头推出来的是 H.265 编码，数据虽然源源不断在推，但浏览器吃不进去。

直接上 ffmpeg，插到代理链路上做实时转码：

```
摄像头 ──P2P──▶ 本机代理(HEVC-FLV) ──ffmpeg──▶ H.264-FLV ──▶ 浏览器
```

```python
cmd = [
    ffmpeg, "-hide_banner", "-loglevel", "error",
    "-fflags", "nobuffer", "-flags", "low_delay",
    "-i", upstream_url,
    "-c:v", "libx264", "-preset", "ultrafast", "-tune", "zerolatency",
    "-c:a", "aac", "-f", "flv", "pipe:1",
]
```

几个点：

- `-preset ultrafast -tune zerolatency`：直播不是压制，延迟比画质重要得多
- `nobuffer` / `low_delay`：少攒缓冲
- 输出走 `pipe:1`，Python 读出来分发给浏览器
- **头部缓存 + 订阅分发**：第一个 subscriber 之前的输出要缓存起来，否则后连的客户端拿不到 `onMetaData` 和 SPS/PPS 序列头，照样黑屏

转码前后对比：

| | 转码前 | 转码后 |
|---|---|---|
| 编码格式 | H.265 / HEVC（浏览器不可解） | **H.264 + 序列头** |
| 播放表现 | 画面一直转圈 | **正常出画面，秒开低延迟** |

再解一次 tag 确认：

```
VIDEO CodecID=7 -> H.264/AVC   AVCPacketType=0 (序列头 SPS/PPS)
AUDIO SoundFormat=10 (AAC)
```

浏览器出画面了。

## 十一、工具

| 工具 | 用途 |
|---|---|
| jadx | APK → Java/Kotlin 源码，主力定位 |
| apktool | 解资源、`AndroidManifest.xml`、布局 |
| radare2 | native 反汇编（`-a arm -b 64`） |
| 自写 ELF 解析器 | 重定位表 → GOT 槽 → 符号名，radare2 没做这件事 |
| Python | 业务接口调用、AES 加解密与中间人代理服务 |
| OpenSSL | 证书签发与独立校验 |
| 厂商公开 P2P SDK | 省掉整套协议逆向，直接拿到 PC 端拉流能力 |
| FFmpeg | HEVC → H.264 实时转码 |
| flv.js | 浏览器端播放 |

## 参考

- **FLV 规范**：Adobe Video File Format Specification v10.1（tag 结构、CodecID 取值表）
- **NIST SP 800-38A**：AES-CBC 官方测试向量
- **FIPS-197**：AES 标准，附录含中间轮值与最终输出
- **RFC 5280**：X.509 v3 结构与扩展编码规范
- **腾讯云 IoT Video / XP2P 文档**：官方 PC SDK 与示例，这条河是踩着它过的

> 再说明一次：分析对象为本人合法拥有的设备，实践范围限于家庭局域网内自用，厂商敏感的密钥、域名、凭证在文中均做了脱敏处理。
