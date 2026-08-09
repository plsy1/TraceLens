# TraceLens Probe 模块化与按需挂载方案

## 目的

TraceLens 必须根据用户在 Capture Console 中选择的功能加载 Probe。未选择的
模块不应仅在 Core 中丢弃事件，而应从源头不挂载对应 BPF program。

优化前存在四个问题：

1. Observer 待机时仍保留 Kernel BPF 链接。
2. 所有 capture 固定挂载 31 个 Kernel tracepoint，文件等无关功能无法关闭。
3. Network 和 DNS 分别监听一批相同 syscall，存在重复执行。
4. 旧 L3-L5 路径按 ProbeSpec 重复加载 object 和 ring-buffer reader，资源模型偏重。

目标不是盲目追求最少的链接数量。一个只在 `connect` 时执行的专用 tracepoint，
通常比监听所有系统调用的通用 `raw_syscalls` hook 更便宜。最终决策必须依据实际
CPU、事件速率和丢包数据。

## 优化前 Probe 基线

### Kernel

旧 Observer 启动时加载 4 个 object，共建立 31 个链接：

| Object | 链接数 | 当前职责 |
| --- | ---: | --- |
| `process.o` | 2 | process exec/exit |
| `network.o` | 16 | connect/close/state 和 6 组 socket I/O entry/exit |
| `dns.o` | 12 | DNS 所需的 connect/send/recv/read/write/close |
| `file.o` | 1 | `openat` 文件上下文 |
| 合计 | 31 | 启动后固定存在 |

该基线需要特别区分：

- `file.o` 当前只观察 `openat`，并没有单独的文件 `read`/`write` Probe。
- `network.o` 中的 `read`/`write` 用于已知 socket 的流量统计。
- `dns.o` 中的 `read`/`write` 用于 connected UDP/TCP DNS 数据。
- `tcp.o` 虽然参与编译，但 Runtime 没有加载，TCP state 已由 `network.o` 处理。
- Stop 只关闭用户态事件接收 gate，并不释放 Kernel 链接。
- PID/进程名过滤主要发生在 Core，Kernel Probe 仍然是系统级触发。

### Userspace

当前旧 Level 模型下，针对一个 OpenSSL 目标：

| Level | 管理 attachment | 实际 uProbe 链接 | Hook |
| --- | ---: | ---: | --- |
| L1/L2 | 0 | 0 | 无 |
| L3 | 5 | 5 | `SSL_connect`、SNI、version、get/set fd |
| L4 | 7 | 8 | L3 + `SSL_read` entry/return + `SSL_write` |
| L5 | 7 | 8 | 与 L4 相同，Core 额外保留原始明文 |

旧实现曾编译独立 `http.o`，同时又使用 `plaintext.o` 完成 HTTP 重组，形成重复路径；
Step 6 已将这些程序合并进唯一的 `openssl.o`。

## 用户界面

Capture Console 增加 Capture profile 和 Modules 区域：

```text
Target
[ Selected PID ] [ Process name ] [ Global ]

Capture profile
[ Process ] [ Connections ] [ Network ] [ Web ] [ Security ] [ Custom ]

Modules
[✓] Process lifecycle       required
[✓] Connections             TCP lifecycle and endpoints
[✓] Traffic counters        upload/download bytes
[✓] DNS                     query, response and domain correlation
[ ] TLS metadata            provider, SNI and version
[ ] HTTP                    metadata and bounded text preview
[ ] Plaintext               sensitive, explicit confirmation
[ ] File activity           openat security context

Effective plan
Kernel links: 18 · Userspace links: 0 · Memory only

[ Start capture ]
```

### 内置 Profile

| Profile | Process | Connections | Traffic | DNS | TLS | HTTP | Plaintext | Files |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Process | 开 | 关 | 关 | 关 | 关 | 关 | 关 | 关 |
| Connections | 开 | 开 | 关 | 关 | 关 | 关 | 关 | 关 |
| Network（默认） | 开 | 开 | 开 | 开 | 关 | 关 | 关 | 关 |
| Web | 开 | 开 | 开 | 开 | 开 | 开 | 关 | 关 |
| Security | 开 | 开 | 开 | 开 | 开 | 关 | 关 | 开 |
| Custom | 用户选择 | 用户选择 | 用户选择 | 用户选择 | 用户选择 | 用户选择 | 用户选择 | 用户选择 |

文件模块默认关闭。用户不选择 File activity 时，`file.o` 不加载、不挂载，
`openat` 不执行 TraceLens BPF program，也不会产生文件事件。

Profile 只是 `CaptureFeatures` 预设，不再叠加 Observation level。用户修改预设
中的任一模块后，Profile 自动切换为 Custom。Plaintext 不进入任何默认 Profile，
每次 capture 都必须由用户显式选择并确认。

### 模块依赖

| 模块 | 依赖 | 说明 |
| --- | --- | --- |
| Process | 无 | 所有其他模块的基础依赖，也可以单独作为 Process Profile |
| Connections | Process | connect/close/state 和 endpoint 关联 |
| Traffic | Connections | socket 上传/下载字节统计 |
| DNS | Connections + Socket I/O | 域名解析和 connection correlation |
| Files | Process | 独立模块，不被其他模块自动启用 |
| TLS | Process + Connections | Provider、SNI、协议版本和 session/fd 关联 |
| HTTP | TLS | HTTP 元数据和有界小型文本预览 |
| Plaintext | TLS | 有界原始明文；敏感模块，要求显式确认 |

UI 勾选高层模块时自动勾选并锁定依赖项，同时在旁边解释原因。后端仍需再次
执行依赖解析，不能信任前端传入的组合。

第一版运行期间不允许修改模块。用户 Stop 回到主界面后选择新计划再 Start，
避免同一个 capture 中不同时间段拥有不同字段却没有明确边界。

## API 和状态模型

### Capture start

`POST /api/capture/start` 扩展为：

```json
{
  "target": "process-name:curl",
  "profile": "custom",
  "modules": ["process", "connections", "traffic", "dns", "tls", "http"]
}
```

兼容策略：旧客户端不传 `modules` 时使用 `network` 默认 Profile，不能继续默认
启用 Files。

### Level 废弃与兼容

新 UI 和新 API 不再产生 `level`。迁移期间旧请求仅在没有 `modules` 时转换：

| 旧字段 | 兼容转换 |
| --- | --- |
| L1 | 使用默认 Network Profile，不增加 TLS 模块 |
| L2 | 与 L1 相同，并返回 deprecated warning |
| L3 | Network + TLS metadata |
| L4 | Network + TLS metadata + HTTP |
| L5 | Network + TLS metadata + HTTP + Plaintext |

当请求同时包含 `modules` 和 `level` 时，`modules` 是唯一有效配置，响应返回
`level ignored` deprecation warning。完成迁移后删除：

- 主界面和 Processes 表中的 Level 下拉框。
- `/api/observations/default`。
- 目标级 L1-L5 upgrade/downgrade API。
- Core 的 `ObservationLevel` 和线性 Probe dependency。

替代模型是 `CaptureFeatures` 位集合和不可变 `CapturePlan`。修改采集内容需要
Stop 回到 Capture Console，再开始一轮新 capture。

### Capture plan

Core 增加不可变的会话计划：

```text
CapturePlan
├── target
├── requested_modules
├── effective_modules
├── kernel_programs
├── userspace_programs
└── capability_warnings
```

`requested_modules` 是用户选择；`effective_modules` 是依赖解析后的结果。API/UI
必须同时展示两者，避免后端自动增加依赖却无法解释。

建议增加：

- `GET /api/capabilities`：模块、依赖、Profile、Runtime 和平台能力。
- `GET /api/capture/plan`：当前请求与实际计划。
- `/api/summary`：增加 active modules 和 Kernel/Userspace link 数量。
- `/api/health`：增加每个 Kernel link、object、program、attach 状态和错误。

Start 必须是事务式操作：验证计划、解析依赖、检查对象、挂载所有必需链接，
全部成功后才进入 Capturing。中途失败必须回滚已经创建的链接并保持 Stopped。

## Probe dependency resolver

Core 引入统一 resolver，输入 Target、Modules 和 Runtime capabilities，输出
确定的 `ProbePlan`：

```text
requested modules
        ↓
module dependency closure
        ↓
TLS provider and privacy capability check
        ↓
platform/provider capability check
        ↓
exact object + program + attach target list
```

Resolver 必须是纯逻辑组件，能够在不加载 BPF 的单元测试中验证。Runtime 只
执行计划，不再自行把线性 Level 猜测成 object 列表。

## Kernel Runtime 生命周期

Kernel Runtime 已拆成控制器和执行线程：

```text
KernelRuntimeController
├── ApplyPlan(ProbePlan)
├── Stop
├── Reset(ProbePlan)
├── Status
└── Shutdown
```

Controller 持有 object、link、ring-buffer reader 和停止信号。状态转换：

```text
Idle
  └─ Start(plan) → Attaching → Capturing
                              ├─ Stop → Detaching → Idle
                              └─ Reset → Detaching → Attaching → Capturing
```

### Idle

- 不加载或挂载 Kernel/Userspace BPF program。
- 进程候选列表直接读取 `/proc`。
- API 和 UI 可用。

### Start

1. 解析并冻结 CapturePlan。
2. 先挂 Process 和 scope 过滤基础设施。
3. 挂 Connections、Socket I/O、DNS、Files 等已选择模块。
4. 根据 TLS、HTTP、Plaintext 模块解析目标 Provider 并挂用户态 Probe。
5. 所有必需模块成功后打开 capture gate。

### Stop

1. 先在 BPF config map 中关闭 active flag，阻止新事件。
2. 停止 Userspace reader 并释放 uProbe links。
3. 停止 Kernel reader 并释放 tracepoint links。
4. 释放 object 和 map handle。
5. 验证当前链接数为 0，再返回 Stopped。

### Reset

Reset 清空会话数据后，使用同一 CapturePlan 执行一次 Stop + Start。更换目标或
模块应先 Stop 回到 Capture Console，再创建新计划。

## Kernel object 重构

### 目标布局

```text
bpf/kernel/
├── process.bpf.c       exec/exit
├── network.bpf.c       connection + shared socket I/O programs
└── file.bpf.c          openat，完全可选

bpf/include/
└── dns_helpers.h       DNS 逻辑，由 network 的 I/O programs 调用
```

### 合并 Network 与 DNS 重复 Hook

`network.bpf.c` 保留 6 组专用 syscall entry/exit：

- `sendto`
- `recvfrom`
- `sendmsg`
- `recvmsg`
- `write`
- `read`

每个 syscall 只挂一组 program。程序读取只读配置 map：

```text
FEATURE_TRAFFIC
FEATURE_DNS
```

处理逻辑：

```text
socket I/O event
    ├─ Traffic enabled → 更新已知 connection 字节数
    └─ DNS enabled + DNS socket → 解析 DNS payload
```

这会把 Network 和 DNS 当前重复的 I/O/连接 syscall 链接合并。不能为了让 UI
显示“只有两个 Hook”改成 `raw_syscalls/sys_enter` 和 `sys_exit`；后者会在系统
所有 syscall 上运行，可能比多个专用 tracepoint 更昂贵。

### 预计 Kernel 链接数

完成第一轮合并后：

| Capture 计划 | Process | Connection | Socket I/O | File | 合计 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Process only | 2 | 0 | 0 | 0 | 2 |
| Connections | 2 | 4 | 0 | 0 | 6 |
| Network 默认 | 2 | 4 | 12 | 0 | 18 |
| Security | 2 | 4 | 12 | 1 | 19 |

相比优化前固定 31 个链接，默认计划降到 18，完整计划降到 19，并且 Files 可以
真正做到 0 Hook。DNS 与 Traffic 同时启用时共用 12 个 Socket I/O 链接。

如果用户只要 Connections，不需要字节统计和 DNS，就不会挂载 12 个高频 I/O
tracepoint。

## Capture scope 下沉到 BPF

仅在 Core 中过滤意味着无关 PID 的事件已经经过 BPF、ring buffer 和用户态
复制。当前每个 Kernel object 都有独立但结构一致的 capture config map：

```text
active
scope_mode: global | pid | process_name
target_pid
target_comm
```

Probe 在 reserve ring-buffer 前执行廉价的 scope 检查。目标级过滤不破坏 DNS
resolver 关联：DNS 模块维护受控的 dependency PID 集合，允许系统 resolver
响应进入 DNS cache，但这些事件不会出现在无关进程的
普通 Timeline 中。

Process-name scope 必须在 Kernel 侧使用 `comm` 做第一层过滤，Core 再根据完整
`/proc` identity 二次验证。固定 PID scope 在 BPF map 中直接比较 PID。

## Userspace Probe 优化

通用 TLS Provider 重构应同时改变资源模型：

- 按 `(provider, library build-id, target scope)` 去重。
- 一个 Provider object 加载一次，按 feature 选择性 attach 其中的 programs。
- 同一 object 使用一个 ring buffer 和一个 reader，而不是每个 ProbeSpec 一个。
- 仅 TLS 模块只挂 metadata programs。
- HTTP 或 Plaintext 在同一个 Provider 实例上增加 read/write programs。
- HTTP 与 Plaintext 可以使用相同底层字节，但保留策略独立；只选 HTTP 时不保存
  原始片段，只选 Plaintext 时可以关闭 HTTP parser。
- TLS metadata、HTTP 重组输入和 Plaintext 共用唯一 `openssl.o`；不保留重复 object。
- 已从构建和源码中移除未加载的 `tcp.o`。
- 修正 `plaintext.bpf.c` 中 write program 的 section 命名，避免未来 auto-attach 错误。

目标不是强行把 8 个 OpenSSL uProbe 链接变成一个，而是只加载一个 object、一个
reader，并确保同一库和符号不会重复挂载。

## 可选的高性能 Backend

在 BTF 和目标内核支持时，可以实验使用 fentry/fexit、cgroup socket 或 sockops
替代部分 syscall tracepoint。它必须作为 capability-controlled backend：

1. 默认保留兼容性更好的 tracepoint 实现。
2. 启动时检测 BTF、program type 和 attach 能力。
3. 两种 backend 输出完全相同的事件 ABI。
4. 只有基准证明 CPU、吞吐和准确性更好时才设为默认。

不能仅凭链接数量选择 backend。

## 指标与诊断

每次 CapturePlan 应记录：

- requested/effective modules。
- Kernel 和 Userspace object 数量。
- 实际 link 数量及 hook 名称。
- 每模块收到、过滤、提交和丢弃的事件数。
- ring-buffer reserve failure 和用户态 channel drop。
- Payload 截断、HTTP 重组放弃和无法关联事件数。
- attach/detach 耗时。
- 捕获进程与 Core 的 CPU、内存基线。

UI 的 Effective plan 只显示简短摘要，详细内容放到 Diagnostics 弹窗和
`/api/health`，避免重新变成看板。

## 实施顺序

### Step 1：契约和 Resolver

- 新增 CaptureFeatures、CaptureProfile、CapturePlan、ProbePlan。
- 扩展 capture API，并保持旧客户端兼容。
- 为依赖闭包和 program 列表补单元测试。

### Step 2：可控制的 Kernel Runtime

- 将永久 `run` 循环拆成 Controller。
- 实现 ApplyPlan、Stop、Reset、Status。
- Stop 后实际 drop Kernel links 和 readers。
- `/api/health` 暴露 Kernel attachment。

### Step 3：Kernel object 拆分与去重

- 在 `network.o` 内按 program 分离 Connections 和 Socket I/O attachment。
- 将 DNS 解析合并到共享 Socket I/O program。
- Files 保持完全独立。
- 清理未使用的 `tcp.o` 和独立 `dns.o`。

### Step 4：主界面 Module UI

- Process、Connections、Network、Web、Security、Custom Profile。
- 删除 Observation level 和所有进程级等级控件。
- 模块勾选、依赖锁定和 Effective plan。
- Files 默认关闭。
- Capture 运行时锁定配置，Stop 后允许修改。
- 空视图说明模块未启用，而不是显示为采集失败。

### Step 5：BPF scope filter

- 已完成 capture config map 和 resolver dependency PID map。
- 已完成 PID、进程名和 Global 的 ring-buffer 前早期过滤。
- 已保留 Core 完整进程身份二次校验，并补充 scope 编码和 resolver 白名单测试。

### Step 6：Userspace object 合并

- 已完成 Provider 实例共享 object、maps、links 和 reader。
- 已按 `(OpenSSL, ELF build-id, target scope)` 去重。
- 已将 TLS metadata 和 bounded payload 程序合并到 `openssl.o`，删除独立
  `tls.o`、`http.o`、`plaintext.o`，并修正 `SSL_write` section。
- bpftime loader 已支持一次接收完整 hook 集合，而不是每个符号启动一个 loader。

### Step 7：性能和 privileged E2E

- 已记录旧 31-link/7-reader 结构基线和新 Profile 矩阵，见 `performance.md`。
- 已对比 Process、Connections、Network、Web、Security 和 Custom Files。
- 已真实验证 kernel uProbe fallback、HTTPS payload、scope 和完整 detach。
- bpftime grouped-loader 已完成编译和单元测试；本机未安装 bpftime，真实注入测试
  保持 capability-gated。当前适配器只接受提供 `trace` 命令的兼容版本；新版
  `load/start/attach` 生命周期迁移属于后续 runtime compatibility 工作。
- 当前数据不足以证明 fentry/sockops backend 应成为默认实现，暂不增加复杂度。

## 测试计划

### Resolver 单元测试

- Process、Connections、Network、Web、Security Profile 的 requested/effective modules。
- Files 永远不会作为其他模块的隐式依赖。
- TLS、HTTP、Plaintext 的 userspace dependency 和隐私策略。
- 不支持的 Runtime 和 Provider 返回结构化 warning/error。

### Runtime 集成测试

- Idle 链接数为 0。
- Process Profile 只挂 Process。
- Connections Profile 只挂 Process + Connection。
- Network 不挂 `file.o`。
- Security 才挂 `openat`。
- Stop 后链接数回到 0。
- Reset 使用相同计划重新挂载且事件存储为空。
- 部分 attach 失败会完整回滚。

### 数据正确性

- Traffic 与 DNS 共用 Hook 后不重复计数或重复 DNS 事件。
- DNS resolver fallback 和 fake-IP domain correlation 不退化。
- 关闭 Traffic 后连接仍存在，但字节数明确显示 unavailable，而不是 0。
- 关闭 DNS 后不显示猜测域名。
- 关闭 Files 后不产生 File event 或相关 Detection evidence。

### UI 测试

- Process、Connections、Network、Web、Security Profile 切换生成正确模块集合。
- 修改预设模块后自动切换为 Custom。
- 依赖项自动选择并锁定。
- Start 请求包含 modules。
- 运行时不能修改计划。
- Stop 返回主界面后可以创建不同计划。
- 未启用模块有明确空状态。

## 完成定义

Probe 模块化完成必须满足：

1. Observer Idle 时 Kernel 和 Userspace attached link 均为 0。
2. 主界面可以选择 Process、Connections、Network、Web、Security 或 Custom。
3. UI 不再出现 L1-L5；CaptureFeatures 是唯一有效配置。
4. Files 默认关闭，未选择时没有 `openat` BPF link。
5. 默认 Network 计划不超过 18 个 Kernel links，完整 Security 不超过 19 个。
6. Network 与 DNS 不再为同一 syscall 各挂一套重复 program。
7. Stop 在返回成功前释放本次 CapturePlan 的所有链接和 reader。
8. PID/进程名 scope 在进入 ring buffer 前完成第一层过滤。
9. API/UI 能展示 requested/effective modules 和实际链接。
10. 关闭模块不会被显示为“0 条结果”，而是明确显示“本次未启用”。
11. 单元、集成、UI、privileged E2E 和性能基准全部可重复执行。
