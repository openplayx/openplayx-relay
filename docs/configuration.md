# Web 配置与权威 JSON

管理器和组件部署是两层：Web 管理器管理本端逻辑配置；固定版本的 sing-box/frp 只读取派生运行文件。Web 页面不提供 shell、任意文件读写或原生 JSON 编辑器。

## 文件与职责

- `relay.json` / `home.json`：本端唯一可编辑连接配置，含 `schemaVersion: 1` 和单调递增的 `revision`。
- `secrets.json`：UUID、frp token 的实际值，普通配置只有 `secret:...` 引用。读取、状态和脱敏导出 API 不返回实际值。
- `tls/`：受控证书与私钥资产；配置只保存相对受控目录的引用。Web 导入最多 128 KiB 的 PEM，服务端生成文件名，不接受浏览器提供的路径。
- `admin.json`：独立管理员密码的 scrypt 校验信息；管理员身份与 App、frpc 身份无关。
- `bootstrap-token` / `bootstrap.json`：首次本机初始化的 15 分钟凭据与校验信息；设置管理员密码后删除。
- `*.backup.json`：上一份已校验逻辑配置，不包含机密实际值。
- `last-good.json`、`status.json`：只读的最近成功运行快照与实际修订，不是另一份可编辑配置。
- `revision.json`：已发放修订计数，保证显式损坏恢复也不复用旧修订。
- `grants.json`（仅 Home）：从可信 Relay 配对目录导入的本机授权，Web 不可编辑。Home 只能选择该家庭、Relay 和已分配服务/映射端口。

持久目录默认 `/var/lib/openplayx-relay/` 或 `/var/lib/openplayx-home/`，目录 0700、配置/机密/资产 0600。组件启动需要的 TLS 文件会复制到受限 release 目录，只给本端组件组读取；组件无法读取管理员或完整机密文件。

## 从已有部署迁移

迁移只读取指定的本机初始配置，若已有权威文件则拒绝覆盖：

```bash
python3 manager/server.py --config-dir /path/to/private-state \
  --import-legacy /path/to/old-deployment.json
```

这一步生成角色 JSON、机密引用和 TLS 副本；不会重启组件或改变线上配置。迁移后停止编辑旧 deployment.json。CLI 的 render/install/update 接受角色 JSON，会从同目录机密引用生成运行配置，不要求在两个地方重复维护参数。

新 Relay 配对工具现在直接输出分离的 `relay/`、`home/` 持久目录和 `app-jellyfin.json`。家庭端只接收 `home/`，它不包含 App UUID 或 Relay 私钥。App 配对文件包含实际客户端机密，应通过可信渠道传递，不能作为脱敏配置公开。

## 启动与安装管理器

本机调试或其他支持 Python 的环境可直接运行（组件控制默认使用 Linux systemd）：

```bash
python3 manager/server.py --config-dir /path/to/private-state \
  --bin-dir /path/to/upstream/bin --runtime-prefix /opt/openplayx-relay
```

将 relay 替换为当前仓库的 home 或 relay；`--bin-dir` 和 `--runtime-prefix` 是本机引导参数，Web 页面无权修改。缺少组件二进制时仍可编辑/保存，组件测试或应用会报告失败，不显示连接成功。

Linux/systemd 安装：

```bash
# 先按 README 安装固定版本组件，再安装本机管理服务。
sudo python3 manager/install.py
sudo systemctl status openplayx-relay-manager
# 卸载仅删除管理服务，保留持久配置和组件数据。
sudo python3 manager/install.py --uninstall
```

安装器将代码和 Web 资源复制到 `/opt/openplayx-relay/management/`，并安装专用 systemd 单元。管理器以本机 root 身份执行固定的组件重启操作，使用 ProtectSystem/ProtectHome 等限制，写入范围限定到本端持久目录与运行前缀。API 不接受命令、可执行文件路径或任意目标文件路径。本次没有在真实 Linux 主机执行安装器。

默认页面：Relay `http://127.0.0.1:9081`，Home `http://127.0.0.1:9080`。首次通过本机终端读取私有目录的 bootstrap-token 登录，15 分钟后过期。需要重新发放时在本机执行 `manager/server.py --config-dir ... --renew-bootstrap`。初始化后请设置至少 16 字符的管理员密码。

推荐从本机或 SSH 端口转发访问。若转发到不同本地端口，需要确保浏览器 Host 位于管理配置允许的来源中；默认同号转发最简单。

```bash
# Relay 示例
ssh -L 9081:127.0.0.1:9081 user@relay.example.com
```

Home 扩展到 LAN 要明确修改 listen、allowedHosts 并先设置管理员密码；Relay 非回环或任何公网管理还必须配置 HTTPS。修改管理监听后，页面只保存，不自行重启管理服务；在本机重启管理服务后再应用组件配置，避免页面把旧监听状态误报成已生效。

## 使用流程

1. 编辑类型化表单；机密留空表示保持，明确清除后若仍有必需依赖则后端拒绝保存。
2. 校验草稿：服务端检查版本、端口、重复服务、授权、凭据引用和 TLS 路径，不依赖前端校验。
3. 测试草稿：生成临时运行配置，运行固定版本的上游校验；Home 另外测试已配置 Relay 的 TCP 可达性。不重启线上组件、不写权威配置，不承诺媒体登录或隧道已经成功。
4. 保存 JSON：携带 expectedRevision；并发修改返回 409。机密先写入，普通 JSON 通过同目录临时文件、fsync 和原子替换保存。保存不会等同于应用。
5. 应用已保存修订：先检查配置，生成 release，复制 TLS 资产，原子切换 current，再按 sing-box → frps/frpc 顺序重启。Home 确认 SOCKS5 握手就绪后才启动 frpc，不存在直连回退。
6. 失败保留已保存期望修订，显示“已保存但未生效”，尝试恢复原 current 和运行配置；成功才更新实际修订并清理不再被当前、备份或最近有效配置引用的机密。

配置与应用修改可能影响活动播放；页面应用前会明确提示。只更新本端，不能声称另一台机器已被一并更新。

普通“恢复上一份配置”也保存为新修订，仍需应用。损坏或未知 schema 不会被默认值覆盖；启动遇到无法读取或不安全的管理配置时仅使用固定回环恢复入口，仍要求管理员认证，且不改写原文件。认证后可选择显式恢复最近已知备份，先以文件哈希检查并发修改，再将原始字节另存为 damaged 文件，生成高于已发放计数的新修订。

## API 与安全边界

- 管理 API 使用 HttpOnly + SameSite=Strict 会话 cookie，30 分钟过期；HTTPS 时附带 Secure。
- 修改接口要求登录会话、独立 CSRF token、JSON 请求、明确 Content-Length 和精确 Origin/Host 匹配；不开放 CORS。静态登录页允许正常跨页面导航，不暴露任何配置。
- 登录有尝试频率限制；请求体、TLS 资产数量与并发请求有上限。日志不记录请求 URL、表单或机密。
- 只读取三个固定 Web 静态资源，没有私钥下载或任意文件 API。
- `GET /api/config`、`/api/status`、`/api/export`；`POST /api/validate`、`/api/test`、`/api/save`、`/api/apply`、`/api/restore`；显式损坏恢复使用 `/api/recovery` 与 `/api/recover`。所有配置/状态接口均需认证。
- 管理监听变化需要本机服务重启；管理器没有停止/重启自身或系统其他服务的 Web API。

单家庭、多服务的授权范围沿用基础部署，不扩展为多租户。当前生成器支持固定版本 VLESS/TLS；新增代理协议需要增加后端 schema、生成器和真实验证，不能在表单中伪装为已经支持。

## 验证

```bash
python3 -m unittest discover -s tests
```

测试覆盖机密不出现在普通 JSON/API、修订冲突、备份恢复、未知/损坏文件保护、哈希恢复、端口/路径/授权拒绝、登录/CSRF/跨域限制和应用失败回退。Relay 的 e2e.py 可加 `--managed-json`，验证由角色权威 JSON 与机密文件生成的真实 sing-box/frp 媒体链路。
