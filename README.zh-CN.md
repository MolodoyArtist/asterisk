# vpnctl

[English](README.md) · **简体中文** · [Русский](README.ru.md) · [فارسی](README.fa.md)

在全新 VPS 上搭建自己的代理：一条命令、网页面板，无需手动修改配置。
代码开源，无数据分析或遥测。凭据在你的服务器上生成。

**[v0.3.0 版本](https://github.com/MolodoyArtist/asterisk/releases/tag/v0.3.0)**

## 安装

准备一台**全新的 Ubuntu 22.04 或 24.04 VPS**：公网 IPv4、x86_64 或 arm64、
至少 512 MiB 内存和 2 GiB 可用磁盘空间。安装程序会配置 Nginx、UFW 和 systemd，
请勿在已有其他服务的服务器上运行。

通过 SSH 登录 VPS，然后粘贴：

```bash
curl -fsSL https://github.com/MolodoyArtist/asterisk/releases/latest/download/install.sh | sudo bash
```

按提示选择是否已有域名。保存安装结束时显示的面板地址、用户名、密码、代理链接和二维码。

## 连接

**没有域名：** 登录 `https://SERVER_IP:9443`，打开 **Devices**，
将 VLESS + REALITY + Vision 链接或二维码导入兼容客户端。

**已有域名：** 登录 `https://YOUR_DOMAIN:9443`，打开 **Devices**：

| 配置 | 客户端 | 导入方式 |
| --- | --- | --- |
| VLESS + XHTTP + TLS | 基于 Xray 的客户端，例如 v2RayTun | 链接、二维码或 Xray JSON |
| Hysteria 2 | sing-box 1.12+ | JSON 文件 |

XHTTP JSON 提供本地 SOCKS 代理，图形客户端负责管理隧道。
原版 sing-box 不支持此 XHTTP 配置。为每台手机或电脑添加单独的设备，删除设备即可撤销访问权限。

## 以后再添加域名

1. 将域名的 **A 记录**指向 VPS IP。在 Cloudflare 中选择 **DNS only**。
   仅当 VPS 的公网 IPv6 正常可用时才添加 AAAA 记录。
2. 在面板中选择 **Domain → Check DNS → Activate XHTTP and Hysteria**。
3. REALITY 将停止工作。断开该连接，登录 `https://YOUR_DOMAIN:9443`，
   在 **Devices** 下载新的配置。

Nginx 提供伪装网站，将随机生成的 XHTTP 路径转发至 `127.0.0.1:5555` 上的 Xray。
Hysteria 直接接收 QUIC，证书自动续期。使用域名并不保证能规避 DPI 或 IP 封锁。

## 可选 Telegram 代理

激活域名后，选择 **Telegram → Enable Telegram proxy**，在 Telegram 中打开生成的链接。
使用 **mtg + FakeTLS**，以你的网站作为伪装，支持消息和媒体传输。通话可能仍需 VPN。

## 端口

在 VPS 提供商的防火墙中放行下列端口；服务器本机的 UFW 规则由 vpnctl 管理。

| 端口 | 用途 |
| --- | --- |
| 你的 SSH 端口 | 登录服务器 |
| 80/TCP | 证书验证 |
| 443/TCP | REALITY；激活域名后改为 Nginx + XHTTP |
| 9443/TCP | 网页面板 |
| 443/UDP | 激活域名后的 Hysteria |
| 8443/TCP | 仅在启用时用于 Telegram |

**5555 仅监听本机。** 伪装网站无法访问管理面板。

## 更新与帮助

再次运行同一条安装命令即可更新至最新发布版本。更新程序会验证配置，失败时尝试回滚。
旧安装的链接会保留，直到你主动激活新的域名方案。升级前请停用旧版 Telegram/padding 配置。

```bash
sudo vpnctl doctor                 # 检查服务和证书
sudo vpnctl admin reset-password   # 重置面板密码
```

面板无法打开时，先检查提供商的防火墙和 DNS。
妥善保存初始凭据后，请删除 `/root/vpnctl-install.json`。
不要公开导出的 JSON、代理链接或服务器日志。

CI 覆盖 Ubuntu 22.04/24.04、配置、FakeTLS 伪装、更新和回滚。
尚未在独立的全新 VPS 上验证完整安装流程。

[安全说明](SECURITY.md) · [MIT 许可证](LICENSE)
