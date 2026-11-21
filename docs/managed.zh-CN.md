# Relay 中心托管模式

`managed --config /etc/openplayx-relay/managed.json` 使用节点专属 machineToken 拉取 `/v1/relay/node/config`，不读取旧的家庭配对配置。配置文件由部署流程写入，仅服务用户可读，云平台和 DNS Token 不进入节点。

## 两类配置

| 分类 | 内容 | 更新方式 |
|---|---|---|
| 基础配置 | 节点身份、监听地址、TLS 身份与证书路径、协议参数、进程日志 | 部署时固定；变更可受控重启或重新部署 |
| 用户策略 | 账号、Connector/设备身份和凭据、服务注册、设备服务授权 | 不可变快照热更新，不重启共享监听器和无关连接 |

API 的 baseRevision 标识节点传输身份，policyRevision 标识 userPolicies/credentials；全局 revision 保留用于有序 ACK。无法支持的基础传输变更会要求重新部署，不会虚假 ACK。配置时间戳仅作刷新参考，不触发过期停服；中心临时不可达或配置无效/倒退时，保留上次成功策略。

## 平滑更新的边界

- 常驻 TLS/VLESS 入口使用 sing-box 同源的上游 VLESS 实现，每次在旁路构造新的只读认证快照，不修改工作线程正在读取的认证表。新握手在转发前再次核对当前身份和授权。
- 每个 Connector 保留独立的回环 frps。新增 Connector 仅创建它自己的实例；新增用户、设备、服务或授权，不重启已有实例、控制通道和传输连接。
- frp 插件同时校验所属 Connector、服务 ID、代理名 `<connectorId>.<serviceId>` 和端口。内部 frps 的允许端口范围放宽给动态注册使用，实际访问仍由插件和 VLESS 网关双重精确授权，端口不向公网暴露。
- 注册冻结锁覆盖“插件批准 → 实际绑定”，防止批准与撤销之间的竞争。提交策略时仅取消被撤销或轮换的身份/服务连接，关闭对应原生 frps 代理并释放端口，完成后才 ACK。
- 删除一个服务不会中断同一 Connector 的其他服务；撤销一个设备授权不会中断其他设备。轮换 Connector 的 frp Token 会重建该 Connector 的实例和相关连接，其他 Connector 保留。
- 手机根据 TCP/TLS 测试结果主动固定节点，后台权限同步不自动切换节点。托管服务端口只能在撤销 ACK 或云实例销毁确认后回收，不能按时间超时直接复用。

managed 模式支持 API 当前生成的 TCP/TLS VLESS 配置，不启用 UDP、VLESS 多路复用或 Vision；旧 sing-box 模式的能力不变。证书更新钩子可重启服务；frp 进程日志只在首次启动初始化，日志参数变更需要进程重启。

## 实时统计

机器认证的 status 主机在 `/health` 旁提供 `GET /live`（同样使用 `Authorization: Bearer <machine token>`）。返回当前有连接的设备和 Connector（类型、所属用户 ID、连接数、真实来源 IP、最早连接时间）、最多 500 条单独连接（服务或 Connector 控制通道、来源地址、开始时间），以及自进程启动以来按身份和整节点累计的字节数。`rxBytes` 是客户端发往 Relay 的字节，`txBytes` 是 Relay 发往客户端的字节；速率由调用方根据两次采样计算。不包含凭据和传输内容。管理后台通过 API 的 `GET /v1/adminzzz/relay/nodes/{nodeId}/live` 读取。

## 验证与限制

运行 `go test ./...`、`go vet ./...`、`go test -race ./...`。真实链路使用原生 sing-box App/Connector 与 frp，在同一条持续收发连接中执行服务/设备/账号新增、授权撤销、服务删除、设备凭据轮换，检查无关连接存活、对应连接关闭、端口释放以及组件身份保留。

固定 frp v0.65.0 源码与定向热更新/并发补丁位于 src/third_party，保留上游 Apache-2.0 版权和许可证。已修复此前发现的通道关闭/发送、控制器指针访问竞争；当前完整 race 测试通过，不代表对上游所有行为完成审计。

userPolicies 的带宽与连接数限额尚未接入运行时硬限额，不能用于精确计费承诺。服务 ready 与每个用户 NAS 实际可达仍是不同指标。
