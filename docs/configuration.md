# Web 配置与权威 JSON

同一个进程里有两层：Web 管理器管理本端逻辑配置；内置的 sing-box/frp 只按“最近一次成功应用”的修订运行。Web 页面不提供 shell、任意文件读写或原生 JSON 编辑器。

## 文件与职责

- `relay.json` / `home.json`：本端唯一可编辑连接配置，含 `schemaVersion: 1` 和单调递增的 `revision`。
- `secrets.json`：UUID、frp token 的实际值，普通配置只有 `secret:...` 引用。读取、状态和脱敏导出 API 不返回实际值。
- `tls/`：受控证书与私钥资产；配置只保存相对受控目录的引用。Web 导入最多 128 KiB 的 PEM，服务端生成文件名，不接受浏览器提供的路径。运行时直接读取这里的文件。
- `admin.json`：独立管理员密码的 scrypt 校验信息（与 Python 版本格式相同，迁移后密码继续有效）；管理员身份与 App、frpc 身份无关。
- `bootstrap-token` / `bootstrap.json`：首次本机初始化的 15 分钟凭据与校验信息；设置管理员密码后删除。
- `*.backup.json`：上一份已校验逻辑配置，不包含机密实际值。
- `last-good.json`：最近一次成功应用的修订，服务启动时据此启动组件；`previous-good.json`：再上一份成功修订，其机密引用在回收时保留。
- `status.json`：实际生效修订与失败状态；`runtime.json`：运行中的服务发布的组件状态，供 CLI `status`/`apply` 读取。
- `revision.json`：已发放修订计数，保证显式损坏恢复也不复用旧修订。
- `grants.json`（仅 Home）：从可信 Relay 配对目录导入的本机授权，Web 不可编辑。Home 只能选择该家庭、Relay 和已分配服务/映射端口。

持久目录默认 `/var/lib/openplayx-relay/` 或 `/var/lib/openplayx-home/`，目录 0700、配置/机密/资产 0600，归服务账户所有。以 root 执行修改配置的 CLI 命令后，程序会把目录内文件的属主恢复为该目录的属主。

## 从旧部署迁移

已有 Python 版本部署：直接 `sudo ./openplayx-relay install`，沿用原持久目录，见 README。

只有旧的扁平 `deployment.json` 时，导入到一个新的私有目录（若已有权威文件则拒绝覆盖）：

```bash
./openplayx-relay import-legacy --config-dir /path/to/private-state --file /path/to/old-deployment.json
```

这一步生成角色 JSON、机密引用和 TLS 副本；不会启动组件或改变线上配置。迁移后停止编辑旧 deployment.json。

`pair` 直接输出分离的 `relay/`、`home/` 持久目录和 `app-jellyfin.json`。家庭端只接收 `home/`，它不包含 App UUID 或 Relay 私钥。App 配对文件包含实际客户端机密，应通过可信渠道传递，不能作为脱敏配置公开。

## 运行与安装

前台运行（调试或无 systemd 的环境）：

```bash
./openplayx-relay serve --config-dir /path/to/private-state
```

`serve` 同时提供管理页并运行组件：启动时若存在 `last-good.json` 就按该修订启动 sing-box/frps；配置无效或组件启动失败时管理页仍可用，状态中组件显示 `failed`。没有应用过任何修订时组件保持停止。

Linux/systemd 安装：

```bash
sudo ./openplayx-relay install
sudo systemctl status openplayx-relay
sudo openplayx-relay uninstall      # 仅删除服务，保留持久配置与 releases
```

服务以专用账户 `openplayx-relay` 运行，使用 ProtectSystem=strict/ProtectHome 等限制，可写范围仅为持久目录，只保留 `CAP_NET_BIND_SERVICE`。API 不接受命令、可执行文件路径或任意目标文件路径。

默认页面：Relay `http://127.0.0.1:9081`，Home `http://<Home局域网IP>:9080`（监听 0.0.0.0）。首次通过本机终端读取私有目录的 bootstrap-token 登录，15 分钟后过期。需要重新发放时执行 `sudo openplayx-relay renew-bootstrap`。初始化后请设置至少 16 字符的管理员密码。

Relay 推荐从本机或 SSH 端口转发访问；Home 默认在家庭局域网内通过 IP 直接访问。若转发到不同本地端口，需要确保浏览器 Host 位于管理配置允许的来源中；默认同号转发最简单。

```bash
# Relay 示例
ssh -L 9081:127.0.0.1:9081 user@relay.example.com
```

### 与代理共用公网 443（内置 SNI 分流）

Relay 可以自己监听公网 443，同时服务 App/Home 的代理连接和 Web 管理页，不需要 HAProxy、Caddy 等外部程序。程序只读取 TLS ClientHello 中的 SNI，不解密内容：

- SNI 等于**当前已应用修订**的 `proxy.serverName`：字节原样转发到回环上的 sing-box（`proxy.listen:proxy.port`），TLS 由 sing-box 终止，App/Home 的地址、端口、UUID 和证书保持原值。sing-box 未运行时连接被关闭。
- 其他 TLS 连接（例如浏览器直接访问 `https://<公网IP>/`）：在进程内交给 HTTPS 管理页，管理页看到的是真实来源地址，登录限流按来源分别计算。
- 非 TLS 或 5 秒内未完成 ClientHello 的连接直接关闭；未完成握手的连接数有上限。

在 `relay.json` 的 `management` 中增加可选的 `frontend`（管理页“公网 TLS 入口 IP/端口”字段）：

```json
"proxy": { "listen": "127.0.0.1", "port": 443, "serverName": "relay.example.com", "...": "..." },
"management": {
  "listen": "127.0.0.1", "port": 9081, "https": true,
  "certificateFile": "tls/<管理证书>.crt", "keyFile": "tls/<管理私钥>.key",
  "allowedHosts": ["localhost", "127.0.0.1", "203.0.113.10"],
  "frontend": { "listen": "203.0.113.10", "port": 443 }
}
```

约束（后端校验）：

- `frontend.listen` 是本机实际公网 IP（不能是回环；`0.0.0.0` 会与回环上的 sing-box 冲突而被拒绝）。`frontend.port` 必须等于 `proxy.port`，因为配对文件和 Home 授权里的端口就是它。
- `proxy.listen` 必须是回环地址；管理页必须开启 HTTPS 并配置受控证书；必须先设置管理员密码。`allowedHosts` 加入公网 IP 或域名，管理证书 SAN 需包含它，自签名证书需要浏览器显式信任。
- 不能与代理、管理页、frps 控制或映射端口的监听冲突。管理页本身仍在回环端口（例如 9081）上，可以继续用 SSH 转发访问。

`frontend` 属于管理入口：保存后执行 `systemctl restart openplayx-relay` 才生效（组件按已应用修订一并重启，会短暂中断播放）。更改 `proxy.serverName` 后，分流按新应用的修订自动生效。验证公网页面、未认证 API 的 401、登录和 Home 隧道恢复后，删除主机防火墙中不再需要的 `9081/tcp` 放行规则。

此前使用 HAProxy 的部署（sing-box `127.0.0.1:443`、管理页 `127.0.0.2:443`）仍可继续运行。改用内置分流时：保存带 `frontend` 的修订，`systemctl disable --now haproxy`，再重启 `openplayx-relay`（内置入口要绑定 HAProxy 原来占用的公网 443）。

Home 默认允许局域网 IP 直连，仍需管理员密码或短期初始化凭据；只接受回环/家庭私有网段请求。实际到达本机接口的字面 IP 自动允许，其他主机名仍须列在 allowedHosts。Home 写请求的 Origin 必须与当前 Host 精确一致。Relay 非回环管理仍必须配置 HTTPS 和管理员密码。修改管理监听后，页面只保存；在本机重启服务（`systemctl restart openplayx-relay`，组件按已应用修订一并重启，会短暂中断播放）后再应用组件配置，避免页面把旧监听状态误报成已生效。

## 使用流程

1. 编辑类型化表单；机密留空表示保持，明确清除后若仍有必需依赖则后端拒绝保存。
2. 校验草稿：服务端检查版本、端口、重复服务、授权、凭据引用和 TLS 路径，不依赖前端校验。
3. 测试草稿：在内存中生成运行配置，执行与 `sing-box check`、`frps verify`/`frpc verify` 相同的内置校验并加载 TLS 资产；Home 另外测试已配置 Relay 的 TCP 可达性。不重启线上组件、不写权威配置，不承诺媒体登录或隧道已经成功。
4. 保存 JSON：携带 expectedRevision；并发修改返回 409。机密先写入，普通 JSON 通过同目录临时文件、fsync 和原子替换保存。保存不会等同于应用。
5. 应用已保存修订：先校验，再在进程内停止旧组件、按 sing-box → frps/frpc 顺序启动新组件。Home 确认 SOCKS5 握手就绪后才启动 frpc，frpc 只经该 SOCKS 连接，不存在直连回退。
6. 失败保留已保存期望修订，显示“已保存但未生效”，并用 `last-good.json` 重新启动上一份运行配置（没有时停止组件）；成功才更新实际修订并清理不再被当前、备份、最近及上一份成功配置引用的机密。

CLI `apply` 对已安装的 systemd 服务执行同样的流程：写入 `last-good.json`、重启服务，并等待服务在 `runtime.json` 中报告该修订的组件均为 active；失败时恢复上一份并报告 applyFailed。

配置与应用修改可能影响活动播放；页面应用前会明确提示。只更新本端，不能声称另一台机器已被一并更新。

普通“恢复上一份配置”也保存为新修订，仍需应用。损坏或未知 schema 不会被默认值覆盖；启动遇到无法读取或不安全的管理配置时仅使用固定回环恢复入口，仍要求管理员认证，且不改写原文件。认证后可选择显式恢复最近已知备份，先以文件哈希检查并发修改，再将原始字节另存为 damaged 文件，生成高于已发放计数的新修订。

## API 与安全边界

- 管理 API 使用 HttpOnly + SameSite=Strict 会话 cookie，30 分钟过期；HTTPS 时附带 Secure。
- 修改接口要求登录会话、独立 CSRF token、JSON 请求、明确 Content-Length 和精确 Origin/Host 匹配；不开放 CORS。静态登录页允许正常跨页面导航，不暴露任何配置。
- 登录有尝试频率限制；请求体、TLS 资产数量与并发连接（32）有上限。日志不记录请求 URL、表单或机密；组件错误写入日志前会去除已知机密值。
- 只提供三个内嵌的 Web 静态资源，没有私钥下载或任意文件 API。
- `GET /api/config`、`/api/status`、`/api/export`；`POST /api/validate`、`/api/test`、`/api/save`、`/api/apply`、`/api/restore`；显式损坏恢复使用 `/api/recovery` 与 `/api/recover`。所有配置/状态接口均需认证。
- 管理监听变化需要本机重启服务；管理器没有停止/重启自身或系统其他服务的 Web API。

单家庭、多服务的授权范围沿用基础部署，不扩展为多租户。当前生成器支持固定版本 VLESS/TLS；新增代理协议需要增加后端 schema、生成器和真实验证，不能在表单中伪装为已经支持。

## 验证

```bash
cd src && go test ./...
```

测试覆盖机密不出现在普通 JSON/API、修订冲突、备份恢复、未知/损坏文件保护、哈希恢复、端口/路径/授权拒绝、登录/CSRF/跨域限制、应用失败回退、配对输出，以及在同一进程中以 Relay 与 Home 两个角色运行真实 sing-box/frp 的媒体链路（`TestEndToEnd`，`go test -short` 跳过）。

已有 Home 回环配置可使用 `sudo ./openplayx-home install --enable-lan`（或已安装后 `sudo openplayx-home enable-lan` 再重启服务），显式保存新修订。该选项仅作用于 Home；Relay 默认回环保持不变。主机防火墙仅放行家庭网段的 TCP 9080，不做路由器公网端口映射。
