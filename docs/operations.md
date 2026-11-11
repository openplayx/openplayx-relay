# 拓扑和运行验收

基线是同机独立进程、共享主机网络命名空间。VPS 的 sing-box 与 frps 在同机；家庭 sing-box 与 frpc 在同机。不能把这里的 127.0.0.1 配置直接拆到两个独立网络命名空间的容器。

```text
App / embedded sing-box
  -> VPS VLESS/TLS ingress (TCP 443)
  -> VPS 127.0.0.1:18096 (frps mapping)
  -> frp tunnel (home sing-box -> VPS -> 127.0.0.1:7000)
  -> home frpc -> NAS:8096
```

VPS 仅开放已选代理 TCP 端口。frps 控制端口、媒体映射均回环监听，不启用管理 dashboard。App 账户只允许已分配媒体端口；home 账户只允许控制端口。其余请求 reject，域名目标也不会绕过 IP 规则。

家庭主机只监听本机 SOCKS5。frpc 的 serverAddr=127.0.0.1 表示 SOCKS 请求的 **VPS 目标地址**，不是家庭主机上的 frps；无 SOCKS 配置的直连 frpc 不属于支持的部署。

## 故障排查

- `systemctl status openplayx-relay-sing-box openplayx-relay-frps` 或 home 对应服务；`journalctl -u <服务名> --since -10min`。不要公开未经检查的上游日志。
- `ss -lntp` 确认代理端口、frps 控制及映射地址符合预期。不要将映射改为 0.0.0.0 来规避连接问题。
- 家庭 `manage.py wait-socks --output /opt/openplayx-home/current/config` 检查本地 SOCKS 入口。成功不等于上游已连通。
- TLS 出错检查时间、serverName、CA、完整证书链及权限。更新后服务读取的是 release 中的证书副本；证书续期后重新 update。不要关闭校验。
- frp 登录失败检查两端 token、additionalScopes、控制端口和专用 home UUID；映射失败检查端口冲突及 allowPorts。
- NAS 不可达时在家庭端验证单个已配置目标，不扫描家庭网段。不自动把 NAS 管理后台加入映射。
- App 鉴权失败须修复媒体账号；401/403 不触发路径反复切换。服务源仍保留，连接失败不应删除媒体库资源。
- Linux systemd 的 `is-active` 只检查进程状态；验收还必须从 App 实际浏览、播放、拖动进度并检查映射可达。

## 验证边界

仓库测试覆盖真实固定版本上游进程的配置校验、TLS、VLESS、frpc 经 SOCKS、媒体认证和 Range 响应；还检查 App/home 权限隔离、未分配端口拒绝、未知 UUID 拒绝、停止家庭 sing-box 后不回退直连。测试在单机回环环境完成，不等价于中国运营商跨境线路、长期播放、移动后台或 Linux 服务管理验收。

每个 relay 实例当前对应一个家庭，多个服务共用 App 身份。需要多人或多家庭隔离时应增加独立身份与 frp 服务端授权机制，不要把共享 token 当作多租户控制。
