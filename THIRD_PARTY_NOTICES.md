# 第三方许可与版权声明

Xray Relay Panel `0.2.2` 的项目代码采用 MIT License，Copyright (c) 2026 yond36，完整文本见 [LICENSE](LICENSE)。第三方组件保持原许可与版权，项目 MIT 许可不替代下列条款。

## 本地收集范围

[licenses/manifest.json](licenses/manifest.json) 按组件列出锁定版本、来源相对路径、复制文件、字节数及 SHA-256。`licenses/go/` 和 `licenses/npm/` 保存本机 Go 模块缓存、`web/node_modules` 中对应锁定版本的原始 LICENSE、COPYING、NOTICE、版权、作者和专利文件，保留完整字节。SQLite 的公开领域声明及二维码代码中的附加版权注释也另行保留。

本次收集覆盖 `go.mod` 中全部 **15 个直接及间接模块**，以及 `web/package-lock.json` 中全部 **35 个非开发 npm 依赖**。非开发图包括前端运行依赖及其传递依赖，也保守保留其中的命令行和 Node.js 分支；这不是逐符号或 tree-shaking 后的最小二进制清单。

另外收集 **66 个已安装开发依赖**的许可文件，以及构建工具链 **Go 1.27.3** 的 `LICENSE` 和 `PATENTS`。共收集 117 个组件的 137 份许可、版权或专利文件/注释。Vite、TypeScript、Rollup 等构建工具的原始许可及其包内声明也在其中；收录开发依赖不表示发行程序包含这些工具。

以下范围不能据本次本地收集声称已完整覆盖：

- 50 个锁定开发/平台可选包在本机未安装：25 个其他平台的 `@esbuild/*`、24 个其他平台的 `@rollup/*`，以及 `fsevents@2.3.3`。没有下载或安装这些包。
- 已安装的 `@esbuild/win32-x64@0.25.12`、`@rollup/rollup-win32-x64-gnu@4.68.0`、`@rollup/rollup-win32-x64-msvc@4.68.0` 没有独立 LICENSE/COPYING/NOTICE 文件。已保留父包 `esbuild` 和 `rollup` 实际提供的许可文本，但没有把父包许可替报为这些平台包独立文件的覆盖证明。
- 本次按依赖包内法律文件收集，并保留已识别的附加源码声明；未完成所有第三方源码内部版权注释的逐文件审计。尤其 `modernc.org/libc` 的 `COPYRIGHT-MUSL` 列出多个源文件适用的附加许可，原文已保留，不能据此声称已逐一判定每个源文件是否进入最终链接结果。
- 模块测试夹具、嵌套 `testdata` 与其他未进入本次依赖清单的工具不属于本次运行依赖覆盖。另行分发工具链、依赖源码、其他架构构建工具或 Xray-core 时，应同时保留其分发物提供的完整声明。

所有 53 个开发依赖缺口均在清单的 `uncovered_components` 中按版本和原因列出。清单中的 `collected` 表示已取得对应法律文件，不表示完成了全部法律义务或二进制组成审计。锁文件中的许可标识只用于索引，以实际保留的原文为准。

## Go 直接与间接模块

以下版本来自 `go.mod`；完整原文位于 `licenses/go/<模块>@<版本>/`，各文件可由清单定位。

| 模块 | 锁定版本 | 许可摘要 |
| --- | --- | --- |
| `github.com/pkg/sftp` | `v1.13.9` | BSD-2-Clause |
| `golang.org/x/crypto` | `v0.37.0` | BSD-3-Clause，附 PATENTS |
| `golang.org/x/net` | `v0.39.0` | BSD-3-Clause，附 PATENTS |
| `modernc.org/sqlite` | `v1.37.1` | BSD-3-Clause；生成的 SQLite 源另有公开领域声明 |
| `github.com/dustin/go-humanize` | `v1.0.1` | MIT |
| `github.com/google/uuid` | `v1.6.0` | BSD-3-Clause |
| `github.com/kr/fs` | `v0.1.0` | BSD-3-Clause |
| `github.com/mattn/go-isatty` | `v0.0.20` | MIT |
| `github.com/ncruces/go-strftime` | `v0.1.9` | MIT |
| `github.com/remyoudompheng/bigfft` | `v0.0.0-20230129092748-24d4a6f8daec` | BSD-3-Clause |
| `golang.org/x/exp` | `v0.0.0-20250408133849-7e4ce0ab07d0` | BSD-3-Clause，附 PATENTS |
| `golang.org/x/sys` | `v0.33.0` | BSD-3-Clause，附 PATENTS |
| `modernc.org/libc` | `v1.65.7` | BSD-3-Clause、LICENSE-GO、COPYRIGHT-MUSL 与内含 netdb 的 MIT 文本 |
| `modernc.org/mathutil` | `v1.7.1` | BSD-3-Clause，保留 mersenne 子目录声明 |
| `modernc.org/memory` | `v1.11.0` | BSD-3-Clause，保留 LICENSE-GO、LICENSE-MMAP-GO、LICENSE-LOGO |

Go 运行时与标准库的原始条款位于 [licenses/go-toolchain/go1.27.3/LICENSE](licenses/go-toolchain/go1.27.3/LICENSE) 和 [PATENTS](licenses/go-toolchain/go1.27.3/PATENTS)。更换工具链版本后应重新核对。

## 前端非开发依赖

以下版本来自 `web/package-lock.json`，已与本机对应包的 `package.json` 版本核对。完整文本位于 `licenses/npm/<包名>@<版本>/`。

| 包 | 锁定版本 | 许可摘要 |
| --- | --- | --- |
| `react` | `18.3.1` | MIT |
| `react-dom` | `18.3.1` | MIT |
| `lucide-react` | `0.468.0` | ISC；原文保留 Feather (MIT) 的版权说明 |
| `qrcode` | `1.5.4` | MIT；另保留 Ryan Day、Kazuhiko Arase 的源码版权及 QR Code 商标声明 |
| `scheduler` | `0.23.2` | MIT |
| `loose-envify` | `1.4.0` | MIT |
| `js-tokens` | `4.0.0` | MIT |
| `dijkstrajs` | `1.0.3` | MIT |
| `pngjs` | `5.0.0` | MIT |
| `yargs` | `15.4.1` | MIT |
| `yargs-parser` | `18.1.3` | ISC |
| `ansi-regex` | `5.0.1` | MIT |
| `ansi-styles` | `4.3.0` | MIT |
| `camelcase` | `5.3.1` | MIT |
| `cliui` | `6.0.0` | ISC |
| `color-convert` | `2.0.1` | MIT |
| `color-name` | `1.1.4` | MIT |
| `decamelize` | `1.2.0` | MIT |
| `emoji-regex` | `8.0.0` | MIT |
| `find-up` | `4.1.0` | MIT |
| `get-caller-file` | `2.0.5` | ISC |
| `is-fullwidth-code-point` | `3.0.0` | MIT |
| `locate-path` | `5.0.0` | MIT |
| `p-limit` | `2.3.0` | MIT |
| `p-locate` | `4.0.0` | MIT |
| `p-try` | `2.2.0` | MIT |
| `path-exists` | `4.0.0` | MIT |
| `require-directory` | `2.1.1` | MIT |
| `require-main-filename` | `2.0.0` | ISC |
| `set-blocking` | `2.0.0` | ISC |
| `string-width` | `4.2.3` | MIT |
| `strip-ansi` | `6.0.1` | MIT |
| `which-module` | `2.0.1` | ISC |
| `wrap-ansi` | `6.2.0` | MIT |
| `y18n` | `4.0.3` | ISC |

## 独立下载的 Xray-core

面板发行包不捆绑 Xray-core。节点管理器在运行时下载未修改、固定版本的官方二进制，并在安装前核对 SHA-256；默认版本为 `v26.10.31`。Xray-core 采用 **Mozilla Public License 2.0 (MPL-2.0)**：

- [该版本官方 LICENSE](https://github.com/XTLS/Xray-core/blob/v26.10.31/LICENSE)
- [对应完整源码](https://github.com/XTLS/Xray-core/tree/v26.10.31)
- [官方二进制发行](https://github.com/XTLS/Xray-core/releases/tag/v26.10.31)

本项目没有修改 Xray-core 源码。选择其他版本时，以该官方 tag 的源码、许可和发行物为准。Xray-core 及其依赖不计入上述面板捆绑依赖的本地许可覆盖；本次没有联网获取其许可原文。另行再分发 Xray-core 二进制时，需要保留适用 MPL 声明、对应源码获取方式及其发行物的第三方声明。

## 233boy/Xray 参考关系

[233boy/Xray](https://github.com/233boy/Xray) 的 GPL-3.0 仓库仅用于参考协议参数关系和管理行为。面板独立实现管理逻辑，没有包含、调用或引用该仓库的脚本源码；该脚本不随面板分发。

## 重新收集

[licenses/collect.py](licenses/collect.py) 仅使用 Python 标准库，将依赖视为字节和 JSON 数据，不导入包、不执行第三方代码、不联网、不安装依赖、不修改清单。从可信目录执行，并将本地缓存和工具链路径作为参数传入：

```sh
python -I /path/to/xray-relay-panel/licenses/collect.py \
  --root /path/to/xray-relay-panel \
  --gomodcache /path/to/go/pkg/mod \
  --goroot /path/to/go
```

依赖或锁文件变更后须重新收集并核对本声明中的数量和版本；脚本保留已有输出，不自动删除旧许可文件。再分发面板的源码或二进制时，应同时携带本文件、项目 LICENSE 和 `licenses/` 中适用的原始许可与版权声明。
