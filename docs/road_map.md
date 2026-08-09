# TraceLens Roadmap

这份文档记录产品方向、实施顺序和验收标准，不记录提交历史、开发对话或
已经失效的界面草案。项目使用方式见根目录 `README.md`，系统边界见
`docs/architecture.md`。

## 产品目标

TraceLens 是一个 Linux 进程感知型网络捕获工具。Core 启动后默认待机，
用户选择 PID、进程名或 Global 范围、Capture Profile 和模块，点击 Start 后才
开始记录本次会话；Stop 停止采集，Reset 丢弃当前内存数据并开始新会话。

TraceLens 需要稳定回答以下问题：

- 哪个进程建立了连接？
- 连接对应哪个 IP、端口和域名？
- 连接何时建立、持续多久、传输了多少数据？
- 目标使用了哪一种 TLS 实现，当前支持哪些采集模块？
- 用户明确启用深度观测后，能否看到 TLS、HTTP 和有限明文？

## 已交付基线

| 能力 | 状态 |
| --- | --- |
| Capture 生命周期 | 默认待机；支持 PID、进程名、Global、Start、Stop、Reset |
| Kernel 元数据 | 进程生命周期、连接、TCP 状态、字节计数、DNS |
| 关联 | Process → Connection → Domain → TLS/HTTP |
| Capture 配置 | UI 和 capture API 已使用 Profile + CaptureFeatures；旧 Observation API 仅作迁移兼容 |
| TLS | 自动检测 OpenSSL-family、GnuTLS、NSS/NSPR、rustls-ffi；统一生成 TLS、HTTP 和有限明文事件 |
| HTTP | 有界 HTTP/1.1 请求/响应重组和小型文本预览 |
| UI | Connections、Processes、Sessions、Raw events 独立分页视图；Linux Tauri 桌面包 |
| 存储 | 默认有界内存；SQLite 历史可选 |
| 测试 | Rust 单元测试、集成测试、API 合约测试、UI 构建检查 |

Kernel Probe 已按 capture 模块动态挂载，Network/DNS 共用 Socket I/O Hook，
Stop 后实际释放所有 Kernel links。PID、进程名和 Global scope 已下沉到 BPF，在
ring buffer reserve 前过滤；DNS resolver 通过受控依赖 PID map 仅参与域名关联。
Userspace Probe 已按 `(provider, build-id, target scope)` 去重，每个 Provider 使用
一个 object 与一个 ring-buffer reader。事件携带 Provider、实际库和 API function；
目标进程延迟 `dlopen` 后会在两秒内重扫并增量挂载。

## 通用 TLS 实施状态

| Milestone | 状态 | 已完成 | 待完成 |
| --- | --- | --- | --- |
| 1 Provider 模型 | 完成 | Provider/Capability catalog、API、事件 `provider/library/api_function` | — |
| 2 自动检测与挂载 | 完成 | `/proc` + ELF + build-id、按库去重、2 秒 `dlopen` 重扫、detach、UI 状态 | — |
| 3 OpenSSL family | 完成 | `SSL_read/write`、`SSL_read_ex/write_ex`、metadata、按导出符号挂载 | 更多发行版兼容矩阵持续扩充 |
| 4 GnuTLS | 完成 | record 双向明文、handshake、fd、SNI、稳定 getter 版本、wget E2E | 未调用 getter 的目标不强读私有 session |
| 5 NSS/NSPR | 完成 | `SSL_ImportFD` 对象白名单、SNI/version、PR_Read/Write、PR_Close、本地双向 E2E | Firefox sandbox 环境持续扩充 |
| 6 Runtime TLS | 策略完成 | 动态 rustls-ffi 深度采集；Go build info/Java 检测及明确 unsupported | Go/Java 仅在有版本化安全 adapter 时逐项开放 |

Linux Desktop 已交付 x86_64 `.deb` 和 AppImage 构建链路。桌面端内置 Core、
BPF objects 和必要运行库，通过 Polkit 授权启动 Core，默认待机，并在窗口退出或
崩溃时回收由自身启动的 Core。后续发行工作聚焦旧版 glibc 构建基线、签名和
多架构产物，不再把桌面壳作为功能缺口。

## 设计原则

1. **工具而不是看板**：没有 Start 就不采集；会话操作必须可预测。
2. **Metadata first**：默认只记录低开销元数据，Payload 必须显式启用。
3. **有界采集**：事件、重组缓冲区和文本预览都必须有明确上限。
4. **Process-centric**：所有可关联事件优先归属到 PID、进程和连接。
5. **能力透明**：不支持的 TLS 实现必须说明原因，不能显示虚假的成功状态。
6. **内存优先**：默认不持久化；SQLite 只用于用户主动启用的历史模式。
7. **按库去重**：Global 模式按实际库文件挂载，不为每个 PID 重复挂同一套 Probe。
8. **模块按需**：未选择的功能不能只在 Core 丢弃事件，而是不应挂载对应 Probe。

## CaptureFeatures 与 Level 废弃

线性 L1-L5 无法准确表达独立的 DNS、Files、Traffic、HTTP 和 Plaintext 组合，
因此 Level 从用户模型中废弃。Profile 只是模块预设，`CaptureFeatures` 是唯一
实际配置：

- Process
- Connections
- Traffic
- DNS
- Files
- TLS metadata
- HTTP
- Plaintext

依赖由 Core 自动解析，例如 HTTP 依赖 TLS 和 Connections，Files 不会被任何
网络模块隐式启用。旧 API 的 L1-L5 在迁移期只负责转换为对应 feature 集合；
新 UI 不再显示等级下拉框。模块切换只影响未来 capture，旧事件可以继续查看，
但不能被误认为是新计划产生的数据。

## 当前优先级

1. Kernel Probe 模块化、按需挂载和 Network/DNS 重复 Hook 合并。
2. 通用 TLS Provider 架构和常见动态 TLS 库支持。
3. Probe 生命周期、全局去重、错误诊断和 privileged E2E。
4. TLS 之上的 HTTP/2 等协议能力。
5. 入站连接、DNS 事务消歧和关联准确性。
6. 打包、安装、权限检查和正式发布流程。

Probe 模块化的详细设计、API、UI、迁移步骤和验收指标见
[`probe_optimization.md`](probe_optimization.md)。

## 通用 TLS 目标

“通用”表示用户无需手动选择 TLS 库。TraceLens 自动检测目标进程实际使用的
TLS Provider，并在同一事件模型和 UI 中提供一致能力。

第一批支持范围：

| 优先级 | Provider | 典型目标 |
| --- | --- | --- |
| P0 | OpenSSL 1.1/3、LibreSSL、动态 BoringSSL | curl、Node.js、Python、常见服务端程序 |
| P1 | GnuTLS | curl、wget、部分系统组件 |
| P2 | NSS/NSPR | Firefox 和 Mozilla 生态程序 |
| 后续 | Go `crypto/tls`、rustls、Java JSSE | 静态编译或语言运行时 TLS |

自研 TLS、完全裁剪符号的静态程序、硬件或可信执行环境中的 TLS 不承诺自动
支持。未知实现只启用可用的 Kernel metadata modules，并返回明确的
unsupported reason。

## Milestone 1：TLS Provider 基础模型

目标：把当前写死的 OpenSSL Probe 列表改造成可扩展 Provider 目录，行为保持
兼容。

交付内容：

- `TlsProvider`：OpenSSL、GnuTLS、NSS、GoTLS、Rustls、Java、Unknown。
- `TlsCapability`：Provider、库路径、build-id、版本、支持模块和失败原因。
- Provider 级符号目录：metadata、read、write、连接关联和 ABI 处理方式。
- TLS/Plaintext 事件增加 `provider`、`library` 和 `api_function` 来源字段。
- API 序列化兼容和现有 OpenSSL 事件迁移。
- Provider 选择、事件解码和兼容性单元测试。

验收标准：

- 现有 OpenSSL TLS metadata、HTTP 和 Plaintext 行为不退化。
- Core 不再通过一个全局静态数组假设所有 TLS 都是 OpenSSL。
- Unknown Provider 不挂 Payload Probe。

## Milestone 2：自动检测和统一挂载

目标：根据目标进程实际加载的库和符号自动选择 Provider。

交付内容：

- 扫描 `/proc/<pid>/maps`、ELF 动态符号、库 inode 和 build-id。
- 支持进程启动后延迟加载 TLS 库，并在库可用后重试挂载。
- 一个进程加载多个 TLS 库时分别记录能力，不盲目选择第一个文件名。
- PID 模式挂载目标进程对应库。
- 进程名模式覆盖当前和之后启动的同名进程。
- Global 模式按 `(provider, inode, build-id)` 去重挂载，每个库映像只保留一套链接。
- Stop、Reset、切换目标和取消模块时释放对应链接和 reader。
- `/api/health` 暴露 Provider、库、符号、挂载和失败详情。

数据流：

```text
/proc maps + ELF symbols
          ↓
TLS provider detector
          ↓
provider probe catalog
          ↓
bpftime / kernel uProbe runtime
          ↓
normalized TLS events
          ↓
Core correlation → API → UI
```

验收标准：

- 同一库被多个进程加载时不会生成重复的 Global Probe 集合。
- 短生命周期目标能在进程名模式下尽早被覆盖。
- 找不到库、符号或权限不足时能给出具体错误。
- 未选择 TLS、HTTP 或 Plaintext 时不存在用户态 TLS/Payload Probe。

## Milestone 3：OpenSSL 家族完整支持

目标：补齐现代 OpenSSL API 和常见兼容实现。

交付内容：

- `SSL_read`、`SSL_write`。
- `SSL_read_ex`、`SSL_write_ex`，正确读取输出长度参数。
- OpenSSL 1.1 和 3.x 兼容矩阵。
- LibreSSL 和动态 BoringSSL 符号检测。
- SNI、TLS version、SSL object 和 socket fd 关联。
- 根据库导出符号选择首选 API，避免 wrapper 内部调用造成重复 Payload。
- 同一线程嵌套调用和 entry/return 配对保护。

验收标准：

- 选择 TLS metadata 后，OpenSSL 构建的 curl 显示 TLS 元数据。
- 选择 HTTP 后能生成 HTTP/1.1 请求和响应事件。
- 明确选择 Plaintext 后能看到有界双向明文。
- `SSL_*_ex` 路径不会丢失实际字节数，也不会重复产生事件。

## Milestone 4：GnuTLS

目标：让使用 GnuTLS 的程序获得与 OpenSSL 一致的 TLS、HTTP 和 Plaintext
用户体验。

交付内容：

- `gnutls_record_recv` 和 `gnutls_record_send` 明文方向采集。
- GnuTLS session、transport fd、SNI 和协议版本关联。
- 负返回值、重试和非阻塞 I/O 处理。
- GnuTLS 构建的 curl/wget 测试 fixture。

验收标准：

- UI 不需要 Provider 选择项。
- 同一个 HTTP 测试在 OpenSSL 和 GnuTLS 下产生一致的规范化事件。
- Provider 特有错误不会污染其他 Provider 的状态。

## Milestone 5：NSS/NSPR

目标：覆盖 NSS TLS，同时避免把普通 NSPR 文件和 socket I/O 当成 TLS 明文。

交付内容：

- 识别 NSS/NSPR 库和支持的符号组合。
- 跟踪被导入 TLS 层的 `PRFileDesc`，只对已确认 TLS 对象采集应用数据。
- NSS session、连接和进程关联。
- Firefox 多进程和 sandbox 条件下的能力报告。
- 普通文件、非 TLS socket 和内部加密 record 的误采集测试。

验收标准：

- 支持的 NSS 客户端能够产生规范化 TLS、HTTP 和 Plaintext 事件。
- 非 TLS 的 `PR_Read`/`PR_Write` 不进入 Plaintext Timeline。
- 无法进入目标进程时明确显示权限或 sandbox 限制。

## Milestone 6：语言运行时 TLS

这些实现没有稳定、统一的动态库 ABI，需要独立兼容策略，不阻塞常见动态 TLS
库的首个通用版本。

### Go `crypto/tls`

- 读取 Go build info 和版本。
- 仅对已验证版本使用对应符号和 ABI。
- 处理静态链接、goroutine 和内部函数变更。

### rustls

- 检测动态符号、调试符号或可用的显式 instrumentation 点。
- 不依赖未经验证的结构体 offset。
- 符号被裁剪时返回 unsupported，而不是猜测内存布局。

### Java JSSE

- 使用独立运行时 instrumentation 模块，不把 JVM 内部 ABI 当成稳定 uProbe API。
- 将输出转换为同一个 TraceLens TLS/Plaintext 事件协议。

验收标准：每个支持项都必须绑定明确的运行时版本矩阵；未知版本默认关闭深度
观测。

## API 和 UI 变化

用户只选择目标、Profile 和 Modules，不增加手工 TLS Provider 选择。

进程候选和运行状态需要展示：

```text
curl    OpenSSL 3.0    TLS · HTTP · Plaintext
wget    GnuTLS 3.8     TLS · HTTP · Plaintext
myapp   Unknown        metadata only
```

API 至少需要提供：

- 进程检测到的 Provider 和库版本。
- Provider 支持的 TLS/HTTP/Plaintext 模块。
- 当前挂载的库、符号和 runtime。
- unsupported、attach failed、permission denied 等结构化原因。
- ring buffer 丢弃、Payload 截断和重组放弃计数。

UI 必须区分“未产生流量”“模块未启用”“Provider 不支持”和“Probe 挂载
失败”，不能都显示成空表。

## 数据和隐私边界

- 未选择 Plaintext 时不保存原始明文 Payload。
- HTTP 模块仅保留解析后的元数据和允许的小型文本预览。
- Plaintext 模块只对用户明确选择的目标暴露有界原始明文，并要求显式确认。
- 图片、音视频、压缩包、未知二进制和大型 Body 只保留元数据与字节数。
- 每事件、每流和整次 capture 都必须有独立上限。
- 默认内存存储；启用 SQLite 时必须明确提示明文持久化风险。
- Provider 检测不能扩大 capture scope，Global 以外不得收集无关 PID 数据。

## 测试计划

### 单元测试

- ELF/`maps` Provider 检测和版本选择。
- 符号优先级以及 read/read_ex 去重。
- 各 Provider entry/return ABI 解码。
- session、fd、connection 和方向关联。
- 模块切换、目标切换、超时和 detach。
- Payload 截断、二进制跳过和 HTTP 重组。

### 集成测试

- 每个 Provider 使用独立的小型 TLS 客户端 fixture。
- 使用本地 TLS 服务，测试请求、响应、分片、非阻塞和连接复用。
- PID、进程名和 Global 三种 capture scope。
- 进程启动前选择、短生命周期进程和运行时延迟加载库。
- 多 Provider、多版本和同一库被多个进程加载。
- Stop 后无新事件，Reset 后无旧数据，切换模块只作用于新的 capture。

### Privileged E2E

- 在具备 BPF 权限的 Linux 环境验证 kernel uProbe fallback。
- 在安装 bpftime 的环境验证真实 attach、事件传输和 detach。
- 验证进程退出、Core 退出和错误路径不会遗留链接或子进程。
- 普通 CI 继续执行编译、事件模型和非特权集成测试；特权测试单独运行。

### 性能基线

- 未选择 TLS、HTTP 或 Plaintext 时不挂用户态 Probe。
- Global 不按 PID 重复挂载同一库。
- 记录各 Profile/Module 组合的 CPU、内存、事件速率和 ring-buffer drop。
- 对比未运行 TraceLens、TLS metadata、HTTP、Plaintext 的吞吐和延迟。
- 任何优化都不能通过取消 scope 过滤或扩大 Payload 上限换取表面性能。
- 当前 Profile 矩阵、旧 31-link 对照和测试环境说明见 `performance.md`。

## 通用 TLS 之后

### Runtime 可靠性

- bpftime privileged E2E 和版本兼容矩阵。
- kernel uProbe fallback 的权限、attach 和 detach 诊断。
- 动态库加载监测，减少短进程首次 TLS 调用丢失。
- Probe/link、reader 和子进程生命周期审计。

### 关联准确性

- 更完整的入站 TCP 连接覆盖。
- DNS transaction 级关联和同 IP 多域名消歧。
- TLS session reuse、连接复用和 fd reuse 处理。
- 明确统计无法关联到连接的 TLS 事件。

### 协议能力

- HTTP/2 帧和 HPACK 元数据解析，继续遵守有界 Payload 策略。
- HTTP/3/QUIC 作为独立项目评估；不能依赖 TCP 或传统 `SSL_read` 假设。
- WebSocket 和长连接只在有明确排查价值时加入。

### 发布和运维

- 支持发行版和内核版本矩阵。
- 安装包、system capability 检查和卸载流程。
- 配置文件正式加载和 schema 校验。
- 本地 API 安全边界和非 loopback 监听警告。
- 可重复的性能报告和发布验收清单。

## 非目标

- 默认持续抓取所有系统明文。
- 从网络密文中无条件恢复任意 TLS 明文。
- 保存视频、镜像、压缩包或大型下载内容。
- 默认启用 SQLite 历史数据库。
- 将 TraceLens 做成无限滚动的常驻风险看板。
- 把 Behavior Graph 或 Risk Score 作为主要捕获交互。
- 在没有版本、符号或 ABI 证据时声称支持任意 TLS 实现。
- 在首个通用 TLS 版本中支持所有语言运行时和自研 TLS 库。

## 通用 TLS 完成定义

首个通用 TLS 版本完成时必须满足：

1. 用户选择 PID、进程名或 Global 后无需选择 TLS Provider。
2. OpenSSL 家族和 GnuTLS 通过真实 privileged E2E。
3. TLS metadata、HTTP、Plaintext 在不同 Provider 上具有一致语义。
4. Global 模式按库去重，不产生每 PID 一套的重复 Probe。
5. Unsupported 和 attach failure 在 API/UI 中可区分。
6. 不产生重复明文事件，不越过 capture scope，不突破 Payload 上限。
7. Stop、Reset、目标切换和取消模块都会释放不再需要的 Probe。
8. 单元、集成、UI 构建和特权测试形成可重复验证流程。

完成上述定义后，再决定 NSS 是否与首个版本一起发布；Go、rustls 和 Java 按独立
兼容矩阵逐项交付。
