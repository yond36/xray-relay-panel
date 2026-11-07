# Xray 中转面板 v0.2.2

v0.2.2 对齐 Xray 的上游用户 ID 规则：VLESS/VMess 支持 1–30 字节自定义字符串以及常见 UUID 格式，保留原始 ID，由核心进行映射。验证记录见 [docs/verification-v0.2.2.md](docs/verification-v0.2.2.md)。

v0.2.1 修复 SOCKS 分享链接中 Base64 用户名与密码的解析，支持标准及 URL-safe 编码、有补位与无补位形式，并保留明文认证格式。补丁验证记录见 [docs/verification-v0.2.1.md](docs/verification-v0.2.1.md)。

基于 Xray-core 的中文代理中转控制台。通过 SSH 管理 Linux 中转服务器，或在面板所在 Linux 主机运行独立的中转服务。入口默认采用 **VLESS + REALITY + Vision**，上游使用第三方提供的代理配置。

```text
客户端 ──入口协议──> 中转节点 ──上游协议──> 第三方代理 ──> 目标网站
```

面板独立管理入口与上游，提供配置校验、分享链接、二维码、订阅、部署任务、回滚和实际出口 IP 检测。协议转换会增加一段网络路径；速度改善取决于线路互联、丢包和拥塞情况。

## 运行环境

- 面板生产环境：Linux、systemd，支持 amd64 / arm64。
- 远程节点：Linux、systemd、SSH 与 SFTP；使用 root，或具备非交互 sudo 权限的专用账户。
- 开发环境：Go 1.24+、Node.js 20.19+ 或 22.12+、npm、Python 3。Windows 可以开发及通过 SSH 管理 Linux 节点。
- 运行时下载的 Xray-core 默认版本：`v26.10.31`，支持手动选择其他官方发布 tag。面板发行包不捆绑 Xray-core；应用节点配置时下载对应架构的官方资产并核对 SHA-256，不自动切换 latest。

## 一键安装与本地管理

公开仓库：[yond36/xray-relay-panel](https://github.com/yond36/xray-relay-panel)。在 Linux/systemd 主机安装最新正式版：

```sh
curl -fsSL https://raw.githubusercontent.com/yond36/xray-relay-panel/main/install.sh | sudo bash -s -- install
```

固定安装本项目的 `v0.2.2`：

```sh
curl -fsSL https://raw.githubusercontent.com/yond36/xray-relay-panel/main/install.sh | sudo bash -s -- install --version v0.2.2
```

安装入口支持 Linux amd64 / arm64，将最新正式版解析为固定 tag，并从同一 tag 下载发行包及 `.sha256`。它先校验 SHA-256、归档路径和文件类型，再安装面板；运行发行程序无需 Go 或 Node.js。安装、升级及卸载需要 Python 3，安装入口会检查并补齐 curl、CA 证书、Python 3、sudo 等必需工具。SHA-256 用于校验下载内容与发布方校验文件一致，不等于独立的签名认证。

安装后可直接使用本地管理命令：

```sh
sudo xray-relay-panel status
sudo xray-relay-panel upgrade
sudo xray-relay-panel upgrade --version v0.2.2
sudo xray-relay-panel uninstall
```

升级会在切换前备份面板程序、完整数据、配置与管理文件，只重启 Web 面板服务；健康检查失败时恢复程序和数据。备份数据库必须同时保留匹配的主密钥以及仍存在的 WAL/SHM 文件。

**默认卸载保留 data 和已运行的 node**：卸载会停止 Web 面板并移除本项目的面板程序、unit、管理入口和 sudoers，保留数据目录、配置、数据库、密钥及已有中转；保留数据时也保留系统账户。已运行的本机独立 node 和远程节点继续运行，已有客户端配置仍可使用，但**面板提供的订阅服务将停止**，客户端无法再从该面板刷新订阅。

需要删除面板数据和本机专用节点时，明确执行：

```sh
sudo xray-relay-panel uninstall --purge --remove-local-node --yes
```

`--purge` 删除能够验证归属的面板数据与配置；`--remove-local-node` 另外停止、移除本机专用 node 及其可验证目录，两者互相独立。`--yes` 跳过破坏性操作的交互确认。**完整清理不可恢复**，会删除数据库、密钥与本机节点配置并中断该节点的中转连接，请先另行备份。远程节点、备份及其他 Xray 服务不会自动清理；无法可靠验证归属的目录会保留并报告原因。

## 构建与启动

在项目根目录执行：

```sh
cd web
npm ci
cd ..
go mod download
python -I tools/build.py --os linux --arch amd64
```

构建结果位于 `dist/linux-amd64/`，包含 `xray-panel` 和 `xray-panel-nodectl`。arm64 构建将 `--arch` 改为 `arm64`。开发机没有 Go 时，可以运行 `python -I tools/bootstrap_go.py .tools`，该脚本在独立目录安装经 SHA-256 校验的官方 Go 工具链。

Linux 安装：

```sh
sudo bash deploy/install.sh dist/linux-amd64
```

安装器创建普通系统账户 `xray-panel`，Web 进程以此账户运行；安装固定路径、root 所有的节点管理程序，并通过限定 sudo 命令完成本机节点操作。它不创建或修改已有的 Xray / x-ui 服务。首次应用本机配置时，才创建面板自己的中转服务。

默认仅监听 `127.0.0.1:8080`。在自己的电脑建立 SSH 隧道，再打开 <http://127.0.0.1:8080> 初始化管理员：

```sh
ssh -p YOUR_SSH_PORT -L 8080:127.0.0.1:8080 YOUR_USER@YOUR_PANEL_SERVER
```

首次访问设置管理员账户；没有预置通用账户或默认密码。公网访问可使用 `deploy/Caddyfile.example` 配置独立 HTTPS 反向代理，并在 `/etc/xray-relay-panel/panel.env` 中设置 `XRAY_PANEL_SECURE_COOKIES=1`。反向代理应保留请求 Host。

Windows 本地预览：

```sh
python -I tools/build.py
.\dist\windows-amd64\xray-panel.exe --data .\.local\panel
```

开发时也可以在项目根目录运行 `go run ./cmd/panel`，并在 `web` 目录运行 `npm run dev`。Vite 将 API 请求转发到后端。Windows 不执行 Linux 本机服务管理；添加 SSH 节点即可管理真实 Linux 服务器。

## 账户与资源归属

- **管理员（admin）**：可全局查看、管理所有用户的配置及查看资源归属，创建 admin / user 账户，并管理注册开关、全局默认核心版本和面板公开 URL。关闭注册时仍可由管理员创建账户。
- **普通用户（user）**：仅能查看、管理自己的配置和 SSH 节点；本机节点仅限管理员管理。
- 公开注册默认关闭，由管理员在“设置”中开启。注册只填写用户名和密码，无确认密码框、邮箱或邀请码；注册得到的账户固定为 user。首次初始化管理员与公开注册是独立流程。
- 新资源归创建者所有；节点不跨用户共享，转发规则关联的节点、上游必须与规则同属一个 owner。管理员编辑他人的资源会保留原 owner，刷新订阅导入也保留来源的 owner。

## 手动选择 Xray-core 版本

“节点管理”和管理员“设置”中的版本选择器从 GitHub 官方 [XTLS/Xray-core Releases](https://github.com/XTLS/Xray-core/releases) 获取最多最近 100 条发布记录，标识预发布版本，并提供刷新、缓存时间及失败提示。获取失败时保留已有缓存和当前选择，无缓存时仍可手动输入 tag。

也可输入列表外的明确官方 tag，可省略 `v` 前缀并使用预发布后缀。保存时校验 tag 格式，实际下载还需对应的官方资产与校验文件可用；指定版本不可用时不会改用 latest。

选择或刷新版本不会自动保存、升级或应用；保存节点后仍需手动点击“应用节点配置”。节点版本留空时，保存会固定为**当时的全局默认版本**；以后修改全局默认不会改变已保存节点的版本。所选核心不兼容时，配置校验失败会在切换服务前中止。

## 添加 SSH 节点

1. 打开“节点管理”，填写 SSH 地址、端口、用户名及密码或私钥。公网分享地址可单独填写，适用于 NAT 或专用管理地址。
2. 测试连接。首次连接只读取 SSH 主机指纹，不发送认证凭据或执行远程命令。
3. 核对指纹后明确确认信任，再进行完整环境检查。
4. 保存节点。检查页面中的已有服务、监听端口及架构，再应用配置。

SSH 节点管理程序由本项目构建，通过 SFTP 上传至新的私有临时目录，操作完成后清理。它仅管理本项目的专用目录和 unit。

Linux 同架构发布包将 helper 与面板放在一起即可。Windows 管理 Linux 或跨架构管理时，先构建对应架构 helper，放到：

```text
<面板数据目录>/helpers/linux-amd64/xray-panel-nodectl
<面板数据目录>/helpers/linux-arm64/xray-panel-nodectl
```

也可用 `XRAY_PANEL_NODECTL` 指向对应架构 ELF 文件的绝对路径。SSH 节点需要能执行此程序及 SFTP；非 root 远程账户需要相应 `sudo -n` 权限。私钥可粘贴，支持带口令的私钥。

## 导入上游与创建中转

在“上游代理”粘贴一条或多条分享链接，也可添加订阅 URL 或导入高级 Xray outbound JSON。面板支持 VLESS、VMess、Trojan、Shadowsocks、SOCKS5、HTTP/HTTPS 常见配置。订阅支持逐行链接、整段 Base64，以及 SIP008 Shadowsocks JSON；刷新后同步对应来源，并保护正在被规则使用的上游。

协议、传输和安全层分别处理，导入不会静默删除关键参数。旧认证、旧传输、插件依赖或核心不支持的组合会返回具体错误。高级 outbound JSON 用于补充上游参数，仍受面板的协议/传输白名单约束，应用前需通过所选核心的配置校验；未支持的组合会明确拒绝。完整 Xray JSON 仅提取选定出站，不接管原配置中的日志、入站、路由或管理接口。

在“转发规则”选择节点、上游与监听端口。默认 REALITY 配置自动生成 UUID、X25519 密钥和 short ID；目标站与 SNI 可修改。目标站需要从中转服务器可达，并满足 REALITY 对 TLS / HTTP/2 等条件的要求。TLS 入口需要提供自己的证书和私钥。

保存规则后，点击“应用节点配置”。保存与应用是不同状态，任务成功后才记录部署修订。一个节点的所有启用规则统一生成一份配置；每个入口明确路由到指定上游，默认出口为拒绝。

分享链接与二维码在本机生成，不调用第三方二维码服务。每个账户在“设置”中复制自己的客户端订阅地址及轮换自己的令牌；个人订阅只包含该账户自己的启用入口，admin 也遵循这一范围，全局管理权限不会扩大个人订阅内容。订阅地址和分享链接包含连接凭据，应按密码保管。

## 出口 IP 与状态含义

“检测出口”在所选中转节点启动受保护的回环 SOCKS 检测进程，使用同一上游 outbound，经代理请求 HTTPS IP 回显服务。它显示实际观察到的 IPv4 / IPv6、耗时、时间和失败原因。

- **节点地址**：客户端连接中转节点的入口地址。
- **上游地址**：第三方代理的连接地址。
- **出口 IP**：一次经该上游访问检测服务时观察到的出口，可能与以上两个地址不同。
- **出口检测通过**：确认中转节点能经上游发起请求；公网入口是否可达仍需真实客户端验证。

IPv6 不可用会单独显示。上游失败时没有直连降级；上次成功结果会保留原检测时间，不能当作当前成功。出口池可能随目标和时间变化。检测耗时是代理 HTTP 请求耗时，不等于完整带宽或客户端 RTT。

## 配置应用与现有服务隔离

面板的中转执行器仅管理：

```text
/opt/xray-relay-panel-node/             二进制、配置与修订链接
/var/lib/xray-relay-panel-node/         运行状态、锁及临时探测
/etc/systemd/system/xray-relay-panel-node.service
```

Web 面板自身使用：

```text
/opt/xray-relay-panel/
/var/lib/xray-relay-panel/
/etc/xray-relay-panel/panel.env
/etc/systemd/system/xray-relay-panel.service
/etc/sudoers.d/xray-relay-panel
```

执行器检查端口占用，先用候选版本执行 `xray run -test`，再切换专用服务。启动失败时恢复上一组二进制与配置；正常应用和回滚会重启本面板自己的中转服务，因此已有的本面板连接可能中断。已有 x-ui、233boy 或其他 Xray 服务不被停止、重启或覆盖，也不修改防火墙、安全组和全局 sysctl。

已应用的规则需要先禁用并成功应用，再删除，以免数据库记录与节点真实状态不一致。节点应用后提供任务记录、日志及手动回滚入口。

## 数据、备份与 v0.1 升级

数据库记录采用 AES-256-GCM 加密，记录类型和 ID 参与认证。主密钥默认在数据目录生成 `master.key`，Linux 权限为 `0600`；也可通过 `XRAY_RELAY_PANEL_MASTER_KEY` 提供 Base64 或十六进制编码的 32 字节密钥。会话仅持久化令牌哈希，API 列表隐藏 SSH 凭据和上游原始出站。

v0.2.0 启动时会自动在单个事务中将 v1 数据库迁移至 v2，保留原管理员及密码哈希、会话、配置、旧个人订阅 URL 和应用状态（含已应用修订）；既有资源统一归原管理员，注册保持关闭。迁移失败会回滚事务。

升级前建议先停止 Web 面板自己的服务，再备份整个数据目录（默认 `/var/lib/xray-relay-panel/`），包含 `panel.db`、仍存在的 `panel.db-wal` / `panel.db-shm` 及 `master.key`，并保留旧版本二进制。启用自定义主密钥环境变量时，另行备份该密钥的独立来源。节点中转服务仍可独立运行；需要恢复节点修订时，另行备份 `/opt/xray-relay-panel-node/`。

回滚面板版本时，须在停面板后**同步还原升级前的数据库与旧二进制**，使用匹配的主密钥，并成套恢复数据库及其 WAL 文件；仅替换旧二进制不能撤销 v2 迁移。恢复后先验证凭据解密和节点状态，再应用配置。

## 验证

```sh
go test ./...
go vet ./...
(cd web && npm run build)
bash -n deploy/install.sh
```

`tools/verify_multiuser.py` 提供隔离回环实例中的多用户 API 检查；公网链路验证须另有明确授权的独立测试环境。公开源码与发行包不包含服务器凭据、管理员登录信息、个人订阅地址或私有实机验收数据。Go 面板进程本身无需 Python；安装与生命周期管理需要 Python 3。

v0.2.0 历史检查摘要见 [docs/verification-v0.2.md](docs/verification-v0.2.md)，涵盖多用户隔离、注册、版本选择和迁移。历史 **v0.1.0** 公网链路和故障恢复摘要见 [docs/verification.md](docs/verification.md)。这些记录保留当时的版本、测试范围、结论与未覆盖环境，不代表对所有协议、架构或网络的持续保证。

## 参考与许可证

项目代码采用 [MIT License](LICENSE)，Copyright (c) 2026 yond36。第三方代码保持各自许可，完整文本及本次本地收集的覆盖范围见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) 和 [licenses/manifest.json](licenses/manifest.json)。Go / npm 的锁定版本由 `go.mod`、`go.sum` 与 `web/package-lock.json` 记录。

参考 [233boy/Xray](https://github.com/233boy/Xray) 的协议参数关系和操作方式，面板独立实现管理逻辑，未包含、调用或引用其 GPL-3.0 脚本源码。运行时使用的 [Xray-core](https://github.com/XTLS/Xray-core) 采用 MPL-2.0，通过官方发布资产独立下载，不捆绑在面板发行包中；对应许可、官方二进制及源码地址见第三方声明。
