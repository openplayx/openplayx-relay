# OpenPlayX Relay

VPS 端的 sing-box + frps 配套部署，家庭端见 [openplayx-home](https://github.com/openplayx/openplayx-home)。App 无需安装外部代理客户端。当前基线使用 **VLESS + TLS**；不保证任意跨境网络的可用性。

固定 sing-box **1.12.12**、frp **0.65.0**。发布包 URL 与官方 GitHub release asset 的 SHA-256 固定在 `versions.lock.json`，安装时先校验再解包。支持 Linux amd64/arm64、systemd、Python 3.10+；本机端到端测试在 macOS arm64 完成，Linux/systemd 部署仍需实际主机验收。

## 配置与安装

准备 VPS 域名和可验证的 TLS 证书。仅开放 TCP 443（或实际配置的代理端口）；7000、媒体映射端口保持回环监听。现有 443 服务须另行安排端口，不能直接覆盖。

```bash
python3 scripts/pair.py --host relay.example.com --tls-name relay.example.com \
  --certificate /etc/letsencrypt/live/relay.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/relay.example.com/privkey.pem
# 私有 CA：另加 --proxy-ca /path/to/ca.pem；不允许关闭证书校验。
# 生成目录已存在会拒绝执行，不隐式轮换密钥。
sudo python3 scripts/manage.py install --config secrets/deployment.json
sudo python3 scripts/manage.py status
```

安装将证书与私钥复制到受限的 release 目录，服务使用 DynamicUser + 专用组读取；原始证书文件权限不被修改。服务证书续期后须再次 update，复制新的证书。

配对文件都包含凭据，须通过可信渠道分别传递：

- `secrets/home.json` 与 `secrets/frps.crt` 交给家庭端；在 home.json 修改家庭目标 IP、端口及证书路径，**不要**传递 `frps.key`。
- `secrets/app-jellyfin.json` 导入 OpenPlayX 的来源编辑表单“家庭远程访问”。默认 Jellyfin；Emby 修改对应逻辑端点；SMB 可设 `smb://nas.home.invalid/Media` 并在两端分配映射端口。
- `secrets/deployment.json`、`frps.key`、代理私钥只保留在 VPS。

默认映射 `jellyfin / 18096`，家庭服务地址 `192.168.50.10:8096` 只是待修改的示例。更多映射须同时修改 relay/home 的 services 和相应 App 配对；不重复或占用控制/代理端口。家庭 IP 只写入家庭配置，不写 App 的远程端点。

`lineId`、`homeId`、`serviceId` 是稳定引用。更换 VPS/证书/协议时保留这些 ID 和已有来源 ID，只更新配对线路；不删除来源或重建媒体库。家庭端与 App 使用不同 UUID。当前一组 relay 配置服务一个家庭：App 可访问该家庭的所有已分配映射，home 仅可访问 frps 控制端口；多家庭应使用独立实例。frp token 不提供跨家庭的映射归属控制。

## 管理与回退

```bash
sudo python3 scripts/manage.py stop
sudo python3 scripts/manage.py start
sudo python3 scripts/manage.py update --config secrets/deployment.json
sudo python3 scripts/manage.py rollback
sudo python3 scripts/manage.py uninstall
```

更新先下载、校验 SHA-256、复制证书、生成配置并通过上游校验，再原子切换 `current`。每次保留原 release 作为备份，`previous` 指向上一份成功版本；服务启动失败时恢复原版本。固定版本升级需要先审核并更新 lock 文件，安装器不自行查询 latest。卸载删除 systemd 服务，保留 `/opt/openplayx-relay` 的配置、证书、版本备份，需彻底清理时由管理员处理。

不安装时可独立生成与检查配置：

```bash
python3 scripts/manage.py render --config secrets/deployment.json --output generated
python3 scripts/manage.py check --output generated --bin /path/to/upstream/bin
python3 -m unittest discover -s tests
python3 -u tests/e2e.py --bin /path/to/upstream/bin \
  --home ../openplayx-home --app-library ../openplayx/native/remote_access/build/libopenplayx_remote.dylib
```

检查依赖原版 `sing-box`、`frps`；端到端测试额外需要 `frpc`、OpenSSL、已编译 App 桥接库。测试创建临时证书与回环进程，并在结束时清理，不安装系统服务。

部署拓扑和故障排查见 [docs/operations.md](docs/operations.md)。

## 上游与许可证

此仓库是独立部署工程，不复制上游代理源码。sing-box 为 GPL-3.0-or-later，附命名限制；frp 为 Apache-2.0。实际分发二进制时须附上所选版本的许可证及适用源代码，见 [sing-box](https://github.com/SagerNet/sing-box/tree/v1.12.12)、[frp](https://github.com/fatedier/frp/tree/v0.65.0)。配置字段以这些固定版本为准，不自动套用最新版文档。
