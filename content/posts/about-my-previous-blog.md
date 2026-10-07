---
title: "关于我的旧博客（从 boatrain 到 Kikyo0x）"
subtitle: "一次 2FA 导致的博客搬家"
date: 2026-10-07T15:30:00+08:00
draft: false
categories:
  - 随笔
tags:
  - 博客
  - GitHub
  - 2FA
  - boatrain
summary: "因换手机且 Microsoft Authenticator 未开云备份，旧 GitHub 账号因 2FA 彻底失联。旧博客 boatrainlsz.github.io 将作为只读归档保留，后续新文章都在这里更新。"
---

旧博客地址：**[boatrain 的博客（https://boatrainlsz.github.io/）](https://boatrainlsz.github.io/)**

之所以有现在这个新站，起因是前段时间换了新手机，而旧手机上的 Microsoft Authenticator 之前没有开启云备份。旧 GitHub 账号（`boatrainlsz`）开着强制 2FA，换机后两步验证码全部丢失，恢复密钥（Recovery Code）也没找到，账号彻底登不进去了。

折腾了一圈无果，索性重新注册了现在的 GitHub 账号 `Kikyo0x`，顺手把博客也重新搭建了一套。

好在旧博客是挂在 GitHub Pages 上的静态站点，域名和内容依然在正常运行。那上面记录了我之前写过的一些实战笔记和读书总结：

- **分布式系统**：《数据密集型应用系统设计》（DDIA）多章节笔记与总结
- **底层与网络**：MetalLB 抓包与二三层浅析、Wireshark 源码构建
- **Go 语言机制**：基于寄存器调用惯例的 Go 接口调用机制
- **业务踩坑**：多叉树遍历与复杂的跨泳道工作项排序实现
- **环境折腾**：开发环境配置、各种实用运维脚本

旧站里的文章就不费劲搬运了，留在那边当作阶段性的只读归档。后续所有的技术折腾、底层逆向和工程踩坑都会在这个新站继续写。
