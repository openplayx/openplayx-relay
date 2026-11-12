# OpenPlayX Relay

VPS 端服务：一个 Go 程序，内含 Web 配置管理、**sing-box 1.12.12**（VLESS + TLS 入口）和 **frps 0.65.0**。家庭端见 [openplayx-home](https://github.com/openplayx/openplayx-home)。App 无需安装外部代理客户端。不保证任意跨境网络的可用性。

sing-box 与 frp 以 Go 库的形式编译进同一个二进制，版本固定在 `src/go.mod` / `src/go.sum`（模块校验和）中。运行时不需要 Python，也不再下载上游二进制。支持 Linux amd64/arm64 + systemd；本机端到端测试在 macOS arm64 完成。

## 构建

需要 Go 1.24+。Go 源码、模块文件和内嵌的 Web 页面（`src/web/`）都在 `src/` 下；除 `src/role.go` 外，Relay 与 Home 两个仓库的 `src/` 内容相同。

```bash
scripts/build.sh                       # dist/openplayx-relay-linux-{amd64,arm64} + SHA256SUMS
scripts/build.sh darwin/arm64          # 其他平台
(cd src && go test ./...)             # 单元测试 + 进程内端到端测试
```

## 配对与安装

准备 VPS 域名和可验证的 TLS 证书。仅开放 TCP 443（或实际配置的代理端口）；7000、媒体映射端口保持回环监听。现有 443 服务须另行安排端口。需要用 `https://<公网IP>/` 直接打开管理页时，可启用内置的 SNI 分流，让代理与管理页共用 443，不需要 HAProxy 或 Caddy（见 [docs/configuration.md](docs/configuration.md)）。

```bash
./openplayx-relay pair --host relay.example.com --tls-name relay.example.com \
  --certificate /etc/letsencrypt/live/relay.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/relay.example.com/privkey.pem
# 私有 CA：另加 --proxy-ca /path/to/ca.pem；不允许关闭证书校验。
# 输出目录（默认 secrets/）已存在会拒绝执行，不隐式轮换密钥。

sudo mkdir -p /var/lib/openplayx-relay
sudo cp -a secrets/relay/. /var/lib/openplayx-relay/   # 已有目录时请勿覆盖
sudo ./openplayx-relay install       # 安装二进制与 systemd 服务（管理页 + 组件）
sudo openplayx-relay apply           # 应用配对生成的修订，启动 sing-box + frps
sudo openplayx-relay status
```

`install` 创建系统账户 `openplayx-relay`，把二进制复制到 `/opt/openplayx-relay/releases/<时间戳>/` 并切换 `current`，链接 `/usr/local/bin/openplayx-relay`，写入 `openplayx-relay.service`（单元参考 `deploy/openplayx-relay.service`），配置目录归该账户所有。服务以该账户运行，只授予绑定 443 所需的 `CAP_NET_BIND_SERVICE`。`apply` 把已保存修订应用到运行中的服务；也可在 Web 管理页中保存后点击“应用”。

配对文件都包含凭据，须通过可信渠道分别传递：

- 整个 `secrets/home/` 目录交给家庭端；其中只有 Home 配置、Home 专属机密、授权和 frps 公共证书，不包含 Relay 私钥或 App UUID。将目录放到家庭端私有持久目录后，通过 Home Web 表单修改家庭目标地址与端口。
- `secrets/app-jellyfin.json` 导入 OpenPlayX“设置 → 远程访问”的来源连接表单（新来源仍兼容原配对入口）。默认 Jellyfin；Emby 修改对应逻辑端点；SMB 可设 `smb://nas.home.invalid/Media` 并在两端分配映射端口。
- `secrets/relay/` 目录及代理私钥只保留在 VPS；实际密钥位于该目录的 secrets.json 与 tls/ 资产中。

默认映射 `jellyfin / 18096`，家庭服务地址 `192.168.50.10:8096` 只是待修改的示例。更多映射须同时修改 relay/home 的 services 和相应 App 配对；不重复或占用控制/代理端口。家庭 IP 只写入家庭配置，不写 App 的远程端点。

`lineId`、`homeId`、`serviceId` 是稳定引用。更换 VPS/证书/协议时保留这些 ID 和已有来源 ID，只更新配对线路；不删除来源或重建媒体库。家庭端与 App 使用不同 UUID。当前一组 relay 配置服务一个家庭：App 可访问该家庭的所有已分配映射，home 仅可访问 frps 控制端口；多家庭应使用独立实例。frp token 不提供跨家庭的映射归属控制。

## 管理与回退

```bash
sudo systemctl stop|start|restart openplayx-relay
sudo openplayx-relay status          # 期望/实际修订与组件状态
sudo openplayx-relay check           # 用内置 sing-box/frps 校验已保存配置
sudo ./openplayx-relay update        # 安装新构建的二进制；启动失败自动恢复原版本
sudo openplayx-relay rollback        # 切回上一个已安装二进制
sudo openplayx-relay uninstall       # 删除 systemd 服务，保留配置与 releases
```

`update` 与 `install` 相同：复制新二进制、切换 `current`、重启并确认服务处于 active，否则恢复原版本。`previous` 指向上一个成功版本，供 `rollback` 使用。上游升级需要修改 `src/go.mod` 后重新构建并审核，程序不会自行查询或下载新版本。配置的回退在 Web 管理页使用“恢复上一份配置”再应用。

证书续期后，在 Web 管理页导入新证书并应用；运行时直接读取配置目录 `tls/` 中的受控资产。

不安装时可独立生成与检查配置：

```bash
./openplayx-relay check  --config-dir /path/to/state
./openplayx-relay render --config-dir /path/to/state --output generated   # 输出含凭据
```

### 从 Python 版本迁移

在已有部署上执行 `sudo ./openplayx-relay install` 即可：它停用旧的 `openplayx-relay-{manager,sing-box,frps}` 单元，复用原 `/var/lib/openplayx-relay` 中的 relay.json、secrets.json、admin.json、TLS 资产和 last-good.json（管理员密码保持有效），新服务启动后按最近一次成功应用的修订运行组件。新服务确认 active 后才删除旧单元文件；启动失败时重新启用旧单元。旧的 `/opt/openplayx-relay/releases/*` 不会自动删除。

部署拓扑和故障排查见 [docs/operations.md](docs/operations.md)。

## 上游与许可证

sing-box 以 GPL-3.0-or-later 授权（另有命名限制），本程序静态链接 sing-box，因此本仓库源码及分发的二进制整体按 **GPL-3.0-or-later** 提供，许可证全文见 [COPYING](COPYING)。frp 为 Apache-2.0。分发二进制时须同时提供对应源码（本仓库及 `src/go.sum` 锁定的模块版本）。上游源码：[sing-box v1.12.12](https://github.com/SagerNet/sing-box/tree/v1.12.12)、[frp v0.65.0](https://github.com/fatedier/frp/tree/v0.65.0)。配置字段以这些固定版本为准。

## Web 配置管理

类型化 Web 表单、管理员登录、草稿校验与测试、保存/应用分离、状态、脱敏导出和备份/损坏恢复。权威配置为 `relay.json`，实际 UUID/token 仅存于私有 `secrets.json`。旧 `deployment.json` 仅作为 `import-legacy` 的显式迁移输入。启动、迁移、权限与验证说明见 [docs/configuration.md](docs/configuration.md)。
