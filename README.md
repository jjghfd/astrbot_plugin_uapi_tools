# astrbot_plugin_uapi_tools

AstrBot 的网络工具插件，使用 Uapi 提供 WHOIS 查询、DNS 查询及 Ping 检测功能。

## 功能特性

- **WHOIS 查询**: 查询域名的注册信息（使用合并转发消息发送，避免刷屏）。
- **DNS 查询**: 查询域名的 DNS 解析记录。
- **Ping 检测**: 检测主机连通性及延迟。

## 安装

1. 将本插件仓库克隆到 AstrBot 的 `data/plugins/` 目录下：
   ```bash
   git clone https://github.com/jjghfd/astrbot_plugin_uapi_tools.git data/plugins/astrbot_plugin_uapi_tools
   ```
2. 安装依赖：
   ```bash
   pip install -r requirements.txt
   ```
3. 重启 AstrBot 或重载插件。

## 使用指令

| 指令 | 说明 | 示例 |
|Data | Description | Example |
|---|---|---|
| `/whois <域名>` | 查询域名 WHOIS 信息 | `/whois google.com` |
| `/DNS <域名>` | 查询域名 DNS 解析记录 | `/DNS cn.bing.com` |
| `/ping <主机>` | Ping 主机检测连通性 | `/ping 8.8.8.8` |

## 鸣谢

- [Uapi](https://uapis.cn) 提供 API 支持
- Trea提供的免费AI编程
