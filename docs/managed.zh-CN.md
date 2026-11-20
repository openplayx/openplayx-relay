# 中心托管 Relay

新增 `managed` 子命令，独立于现有 `serve` / `pair` 单家庭模式，不读取或转换旧的 relay.json。

```sh
openplayx-relay managed --config /var/lib/openplayx-relay-managed/managed.json
```

配置由 API 的 Vultr 初始化流程安全写入，包含 apiOrigin、nodeId、machineToken、host、certificate、key、releaseTag、releaseCommit、binaryVersion。文件仅服务用户可读。程序校验 HTTPS 中心地址、固定节点身份、受支持的配置 schema、单调递增 revision、最长 30 分钟有效期及自身 binaryVersion。

托管节点每 20 秒获取中心 `/v1/relay/node/config`。首次启动无本地缓存授权；更新时先关闭旧连接，再应用身份/端口规则，成功后 ACK。独立租约监视器每秒检查一次，到期关闭 sing-box/frps，不会因网络请求卡住而继续使用过期权限。无效配置不会复活旧策略。

## 身份与注册隔离

VLESS 入口按 Connector/设备的独立 UUID 认证，只允许访问该身份的回环控制端口或授权服务端口，最后一条规则拒绝其余目标。

frp 的原生 Token 同时用于认证和控制流加密，不能只在登录插件中替换成共享 Token。因此托管模式在同一进程内为各 Connector 启动独立的回环 frps，使用该 Connector 的原生凭据；sing-box 按已验证的 Connector 身份将逻辑 7000 端口转向对应回环监听。原始 frps 端口不暴露给客户端。插件再次校验 Connector 身份、时间凭据和 TCP remotePort 归属，阻止跨 Connector 注册。

当前实现身份/端口授权、配置应用/撤销及租约失效关闭；userPolicies 中的带宽与连接数配额尚未接入专门的运行时限速器，不能作为精确流量计费或硬配额承诺。

## TLS 与健康检查

公网 443 通过现有 SNI 分流器共享：节点域名转入 VLESS，status.<节点域名> 转入最小 HTTPS 健康接口。健康接口需要节点自身机器 Token，只返回节点 ID、托管协议版本、发布 tag/commit、实际 binaryVersion、已应用/ACK 的配置版本和组件状态。

只有完成配置应用并 ACK 的进程才返回 active。证书/私钥只在本机，ACME 使用 80 端口；中心创建 DNS-only 记录，不能用 Cloudflare 普通 HTTP 代理承载 VLESS。API 自动安装脚本会配置证书续签后的本地复制及服务重启。

## 发布与联调

先运行 `go vet ./...`、`go test ./...`；托管测试含真实 VLESS → frps → Connector → HTTP 媒体访问、未授权端口拒绝及租约失效关闭。还可使用 `go test -race -run Managed ./...` 检查并发。

通过现有构建脚本/CI 发布 amd64 Linux 产物，在 API 中配置固定发布 tag、commit、下载 URL、SHA256 和 binaryVersion。Jenkins 的产物版本一般去掉 tag 的 v 前缀；两者分别记录，不要随意改为 latest。兼容原始二进制或已有 tar.gz 发布包。

这不会将旧 App/Home 自动迁移为中心订阅客户端；原来的配对模式继续工作。中心托管客户端应使用各自的 account/device/connector API 身份和下发配置，不可复用用户密码、节点 Token 或管理员 Token。

### 并发检查的已知限制

自有策略/插件/配置同步可以独立运行 `go test -race -run '^TestManaged(Policy|FRPPlugin|Sync)' ./...`。完整媒体链路的 race 检查会触发固定 frp v0.65.0 上游的 client/proxy wrapper.Stop 与 health callback、server/control worker 与 RegisterWorkConn 的 channel close/send 竞态；本次没有修改或升级上游库，不能将完整 race 检查列为通过。常规真实链路测试通过。
