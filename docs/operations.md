# 拓扑和运行验收

VPS 上的 sing-box 与 frps 运行在同一个 `openplayx-relay` 进程中；家庭端的 sing-box 与 frpc 运行在同一个 `openplayx-home` 进程中。两端都使用主机网络命名空间，配置中的 127.0.0.1 指同一台主机，不能拆到两个独立网络命名空间的容器。

```text
App / embedded sing-box
  -> VPS VLESS/TLS ingress (TCP 443)
  -> VPS 127.0.0.1:18096 (frps mapping)
  -> frp tunnel (home sing-box -> VPS -> 127.0.0.1:7000)
  -> home frpc -> NAS:8096
```

VPS 仅开放已选代理 TCP 端口。frps 控制端口、媒体映射均回环监听，不启用管理 dashboard。App 账户只允许已分配媒体端口；home 账户只允许控制端口。其余请求 reject，域名目标也不会绕过 IP 规则。

家庭主机只监听本机 SOCKS5。frpc 的 serverAddr=127.0.0.1 表示 SOCKS 请求的 **VPS 目标地址**，不是家庭主机上的 frps；frpc 固定使用 `transport.proxyURL`，没有直连模式。

## 故障排查

- `systemctl status openplayx-relay`（家庭端 `openplayx-home`）；`journalctl -u openplayx-relay --since -10min`。组件与管理器日志在同一个单元里；组件错误写入前会去除已知机密，但仍不要公开未经检查的日志。
- `sudo openplayx-relay status` 查看期望/实际修订和 sing-box、frps 组件状态（`active`/`inactive`/`failed`）。
- `ss -lntp` 确认代理端口、frps 控制及映射地址符合预期。不要将映射改为 0.0.0.0 来规避连接问题。
- `sudo openplayx-relay check` 用内置校验检查已保存配置；`render --output DIR` 输出派生配置（含凭据，查看后删除）。
- TLS 出错检查时间、serverName、CA、完整证书链及配置目录 `tls/` 中文件的属主与权限。不要关闭校验。
- frp 登录失败检查两端 token、additionalScopes、控制端口和专用 home UUID；映射失败检查端口冲突及 allowPorts。
- NAS 不可达时在家庭端验证单个已配置目标，不扫描家庭网段。不自动把 NAS 管理后台加入映射。
- App 鉴权失败须修复媒体账号；401/403 不触发路径反复切换。服务源仍保留，连接失败不应删除媒体库资源。
- systemd `is-active` 和组件 `active` 只说明进程与组件已启动；验收还必须从 App 实际浏览、播放、拖动进度并检查映射可达。

## 验证边界

`src/` 下的 `go test ./...` 在单机回环环境中以 Relay、Home 两个角色运行内置的 sing-box 与 frp，覆盖配置校验、TLS、VLESS、frpc 经 SOCKS、媒体认证和 Range 响应；还检查 App/home 权限隔离、未分配端口拒绝、未知 UUID 拒绝、停止家庭 sing-box 后不回退直连。这不等价于中国运营商跨境线路、长期播放、移动后台或 Linux 服务管理验收。

已知上游问题：frp 0.65.0 的 frpc 在停止时有两处无锁读写（`go test -race` 可见，位于 frp 自身代码），只在 Home 应用新修订或停止服务时触发。

每个 relay 实例当前对应一个家庭，多个服务共用 App 身份。需要多人或多家庭隔离时应增加独立身份与 frp 服务端授权机制，不要把共享 token 当作多租户控制。
