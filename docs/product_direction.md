# TraceLens 产品方向

本文定义 TraceLens 当前阶段的产品定位、目标用户、实际应用场景、能力边界和
后续功能优先级。工程架构见 [`architecture.md`](architecture.md)，具体实施顺序见
[`road_map.md`](road_map.md)。

## 产品定位

TraceLens 是一个 **Linux 进程级网络故障诊断与按需抓取工具**：

> 无需配置代理、安装证书或修改目标程序，按 PID、进程名或全局范围捕获网络
> 行为，并将 Process → DNS → TCP → TLS → HTTP 关联成一条可读的诊断链路。

TraceLens 的主要用户是 Linux 开发者、运维和安全排障人员。它首先要解决
“某个程序访问了什么、为什么失败、慢在哪里”这类具体问题，而不是成为常驻
监控看板或同时替代抓包器、APM 和 EDR。

## 核心问题

一次 capture 应尽可能直接回答：

1. 哪个进程发起了网络访问？
2. 它解析、连接到了哪个域名、IP 和端口？
3. DNS、TCP、TLS 和 HTTP 各阶段是否成功？
4. 请求和响应的元数据及允许展示的文本内容是什么？
5. 失败、延迟或异常发生在哪个阶段？

如果界面只展示底层事件，却不能帮助用户回答这些问题，该能力不算完成。

## 产品原则

1. **按需捕获**：Core 默认待机，只有用户点击 Start capture 后才挂载所选模块。
2. **Process-centric**：所有可以关联的数据优先归属到进程和连接。
3. **诊断优先**：优先展示结论、阶段和失败原因，Raw events 只作为高级证据。
4. **Metadata first**：默认采集元数据；原始明文必须由用户显式选择并确认。
5. **有界采集**：事件数量、重组缓冲区、Body 预览和内存占用都必须有上限。
6. **能力透明**：未启用、无流量、不支持、挂载失败和数据丢失必须明确区分。
7. **模块按需**：Modules 是实际挂载依据；Profile 只是预设，Level 只保留兼容转换。
8. **本地优先**：默认只保存在内存；SQLite 和任何敏感内容持久化都必须显式启用。

## 当前可用场景

### 进程外联排查

- 查看某个 PID 或进程名建立的 TCP 连接。
- 将远端 IP、端口与 DNS 域名关联。
- 查看连接状态、持续时间和上下行流量。
- 在 Global 模式中发现未知外联进程，再缩小到具体目标抓取。

### HTTPS/API 调试

- 自动检测 OpenSSL-family、GnuTLS、NSS/NSPR 和动态 rustls-ffi。
- 查看 TLS Provider、SNI、TLS 版本和实际 Hook 来源。
- 在受支持的 TLS 路径中观察 HTTP/1.1 请求、响应和有界文本 Body。
- 解码有界 gzip、deflate、Brotli 和 Zstandard 文本响应。

### 临时安全调查

- 查看陌生域名、异常连接和大量上传。
- 结合进程、连接、DNS、TLS 与文件访问事件进行本地调查。
- 通过 Core 的 alerts、risk score 和 behavior graph API 获取基础检测结果。

这些能力适合短时、目标明确的诊断。目前的告警规则和展示不足以将 TraceLens
称为成熟 EDR。

## 明确的非目标

当前阶段不把 TraceLens 定位为：

- 常驻主机监控或运营大屏；
- 完整数据包抓取和协议分析器；
- 分布式 APM 或 OpenTelemetry 后端；
- 企业级 EDR、SIEM 或远程主机管理平台；
- HTTP 代理、流量修改或重放工具。

如果未来进入其中某个方向，应单独评估产品模型和架构，不能让这些需求破坏
本地、按需、有界的抓取体验。

## 当前能力边界

- HTTP 深度解析目前主要覆盖 HTTP/1.1。
- Firefox、Chrome 和现代服务常用 HTTP/2 或 HTTP/3；即使已抓到 TLS 明文，
  当前也可能只能看到无法直接阅读的二进制协议数据。
- HTTP/3/QUIC 不经过传统 TCP/TLS 数据路径，需要独立的 Provider 和协议适配。
- Go `crypto/tls`、Java JSSE、静态 rustls 和裁剪符号的自定义 TLS 尚无通用安全
  深度适配器。
- 当前缺少完整的 DNS/TCP/TLS/HTTP 分阶段耗时、TCP 重传、RTT、丢包和明确
  失败归因。
- capture 的筛选、搜索、保存、导出和分享能力仍不足。
- 本地 API 没有面向远程多用户场景的认证、TLS 和权限模型。

## 后续优先级

### P0：让 Web 抓取真正可读

- 解析 HTTP/2 frame。
- 支持 HPACK Header 解码。
- 按 stream 配对并发请求和响应。
- 展示 `RST_STREAM`、`GOAWAY` 和协议错误。
- 验证 Firefox/Chrome NSS 多进程与 sandbox 场景。
- 明确显示“已捕获 TLS 明文，但应用协议暂不支持”。
- 支持 HTTP transaction 的进程、域名、状态和文本搜索。
- 为 JSON、HTML、XML 等文本 Body 提供易读视图。

验收标准：使用 Firefox 或常见 HTTP/2 客户端访问测试服务时，用户能够看到按
stream 配对的 method、URL、status、headers、时序和允许展示的文本 Body，而不是
原始 TLS fragment。

### P0：提供分阶段故障诊断

- DNS 查询耗时和失败原因。
- TCP connect 耗时、拒绝、超时和 reset 原因。
- TLS handshake 耗时、版本、Provider 和握手失败原因。
- HTTP 首字节时间和请求总耗时。
- TCP RTT、重传和丢包迹象。
- 在连接详情中给出“失败发生在 DNS/TCP/TLS/HTTP”的明确判断和证据。

验收标准：对 DNS 失败、连接拒绝、TLS 握手失败、HTTP 5xx 和慢响应各准备一个
可重复测试，TraceLens 能正确标出故障阶段并展示关键时间。

### P1：降低 Global 噪声

- 支持排除进程、端口、地址和域名。
- 默认折叠系统服务和无关短连接。
- 按进程、域名和远端聚合连接及流量。
- 常驻展示事件速率、队列丢失和 ring-buffer 丢失。
- 高事件速率下支持有界采样或限速。
- 从 Global 结果一键以 PID 或进程名重新抓取。

Global 用于发现未知目标；深入分析应优先引导到 PID 或 process-name scope。

### P1：形成可交付的诊断案例

- 将一次 capture 保存为带配置和环境信息的案例。
- 导出结构化 JSON 和可阅读 HTML 报告。
- 导出筛选后的连接、HTTP transaction 和关联事件。
- 保存内核、模块、目标、TLS Provider、能力限制及丢失计数。
- 支持标记重要连接并比较两次 capture。

验收标准：用户可以把一个不依赖运行中 Core 的报告附到 issue，其他人能从报告
中理解目标、时间线、失败阶段、关键请求以及数据完整性限制。

### P2：可选安全调查能力

- 告警和行为图 UI。
- 可配置规则、allowlist 和风险解释。
- 进程树、用户、容器、可执行文件 hash、ASN/GeoIP 和威胁情报。
- SQLite 保留策略和敏感数据生命周期控制。

远程 Agent、集中管理、RBAC、审计和防篡改属于独立的企业安全产品阶段，不纳入
当前本地诊断工具的默认范围。

## 推荐的信息架构

- **HTTP requests**：以 transaction 为中心展示请求、响应、时序和文本 Body。
- **Connections**：以网络连接为中心展示进程、端点、域名、状态、流量和诊断详情。
- **Processes**：用于发现目标、理解进程网络占用并缩小抓取范围。
- **Raw events**：用于验证底层证据和处理尚未聚合的高级问题。

同一份连接数据不应再拆成重复的 Connections 和 Sessions 页面。更深的连接活动、
TLS 信息和关联事件应从 Connections 的详情入口查看。

## 近期实施顺序

1. 建立 HTTP/2 fixture、frame/HPACK 数据模型和非特权单元测试。
2. 完成 HTTP/2 request/response stream 配对并接入现有 HTTP transaction UI。
3. 增加 DNS、TCP、TLS、HTTP 阶段时间模型及失败分类。
4. 重构 Connection details，优先展示诊断结论和阶段耗时，再展示原始事件。
5. 增加过滤、搜索和 Global → scoped capture 工作流。
6. 增加 capture 案例保存与 HTML/JSON 导出。

每一阶段都必须保持按需挂载、Stop 完全 detach、内存有界、隐私模块显式确认，
并通过 PID、process-name 和 Global 三种 scope 的回归测试。
