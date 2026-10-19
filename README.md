# myrules

个人专属 Shadowrocket 规则与去广告模块，支持 GitHub Actions 每日全自动同步与聚合。

## 📦 模块订阅地址

| 模块名称 | 订阅链接 | 说明 |
| :--- | :--- | :--- |
| **🚀 全功能去广告聚合模块 (推荐)** | `https://raw.githubusercontent.com/lujundaren/myrules/main/dist/merged.sgmodule` | 聚合通用 UDP 443 阻断、HTTPDNS/移动广告平台拦截、可莉生态 252+ 应用去广告增强（含 JS 脚本）、秋风 AWAvenue、微信、QQ、B站、知乎、微博等全部精细化规则 |
| **🌸 可莉插件中心全量转换模块** | `https://raw.githubusercontent.com/lujundaren/myrules/main/dist/kelee_all.sgmodule` | `hub.kelee.one` 官方全部 275 个插件 100% 完整转换版（含全部去广告、功能增强、签到任务、BoxJs、Sub-Store、YouTube 双语翻译等规则与 JS 脚本） |
| **🛡️ 通用网络基础模块** | `https://raw.githubusercontent.com/lujundaren/myrules/main/modules/general.sgmodule` | 强制阻断 UDP 443 (QUIC/HTTP3)，促使各 App 回退标准 TCP 流量以保证 MITM 解密与去广告 100% 生效 |
| **🌐 HTTPDNS 拦截器** | `https://raw.githubusercontent.com/lujundaren/myrules/main/modules/Block_HTTPDNS.sgmodule` | 拦截各大厂商 HTTPDNS 直连解析，杜绝绕过系统 DNS |
| **📱 移动广告平台拦截器** | `https://raw.githubusercontent.com/lujundaren/myrules/main/modules/Block_Advertisers.sgmodule` | 拦截穿山甲、优量汇、快手联盟、百度联盟、泛连等主流 SDK |
| **✨ 可莉去广告增强补全** | `https://raw.githubusercontent.com/lujundaren/myrules/main/modules/Kelee_Enhance.sgmodule` | 补齐 252+ 个高频应用与小程序去广告（含 HTTP-Request/Response 脚本与重写） |

---

> 📝 **NOTE:**
> 如需单独使用脚本与重写功能，请在 Shadowrocket 中开启 **HTTPS 解密 (MITM)** 并安装/信任证书。
