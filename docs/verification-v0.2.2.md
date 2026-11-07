# v0.2.2 自定义用户 ID 导入修复验证摘要

验证日期：2026-11-07。本补丁修复 VLESS 分享链接使用自定义用户 ID 时被面板拒绝的问题。以下为既有验证结果的公开摘要，整理时未重跑测试。

## 修复范围

VLESS/VMess 上游校验允许 Xray 支持的 1–30 字节自定义字符串、标准 36 字符 UUID 和连续 32 位十六进制 UUID。长度按 UTF-8 字节计算，保留原字符串，由用户选定的实际核心映射。入口 UUID 生成逻辑不变。

空 ID、超过自定义长度上限的普通字符串及无效 UUID 继续拒绝。相应回归测试使用真正超过长度限制的无效值。

Xray 官方源码中，VLESS 和 VMess 使用同一转换路径：

- [v26.10.31 common/uuid/uuid.go](https://github.com/XTLS/Xray-core/blob/v26.10.31/common/uuid/uuid.go#L67)
- [v1.8.24 common/uuid/uuid.go](https://github.com/XTLS/Xray-core/blob/v1.8.24/common/uuid/uuid.go#L67)

## 历史验证结果

- `go test ./...`、`go vet ./...` 通过，包含上一版 SOCKS Base64 认证回归测试。
- 新增 24 项用户 ID 用例通过，覆盖 VLESS/VMess、数字与命名 ID、30/31 字节边界、中文 UTF-8 字节边界、两种 UUID 格式及无效值。
- 合法用例生成的配置通过官方 `v26.10.31` 和 `v1.8.24` 二进制的离线检查；VLESS 覆盖 REALITY 和 Vision。
- 隔离 API 导入和存储检查通过，确认原始 ID、目标参数、REALITY 参数及 Vision flow 保留；相应配置通过上述两代核心的离线检查。
- Windows amd64、Linux amd64、Linux arm64 构建通过。前端未修改，复用既有构建资源。
- Linux amd64 的 `0.2.1` → `0.2.2` Web 面板升级及兼容性检查通过。既有 x-ui、Xray 和独立中转核心的进程启动状态、程序与配置完整性、监听状态在面板更新前后保持一致。

## 未覆盖环境

导入及离线配置检查不连接第三方上游，配置合法不代表网络可达。ARM64 未进行实机运行；本次补丁未重跑所有协议的公网链路测试，未重新构建前端。

本记录描述用户 ID 修复的历史验证，未覆盖随后新增的 GitHub 发行包下载、全新安装、升级失败回滚或完整卸载实机流程；这些流程需要独立的发行验证。其他历史范围见 [v0.2.0 验证摘要](verification-v0.2.md) 和 [v0.1.0 验证摘要](verification.md)。
