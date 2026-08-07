下面这版我把定位、架构、MVP、模块、数据模型、UI、观测等级、bpftime/eBPF 分工都整理成一份，基本可以直接扔给 Codex。

# TraceLens 项目完整规划

## 1. 项目定位

项目名称：

TraceLens

项目定位：

基于 eBPF 与 bpftime 的进程感知型网络安全观测工具。

英文描述：

TraceLens — Process-aware Network Security Observability with eBPF and bpftime

核心目标：

TraceLens 不以“抓包”为中心，而是以“进程网络行为”为中心。

它需要回答：

- 哪个进程建立了这个连接？
- 这个进程连接了哪个域名和 IP？
- 这个连接什么时候建立、持续多久、上传下载多少数据？
- 这个连接是否存在异常行为？
- 这个进程在建立连接前后还做了什么？
- 这个 TLS 连接实际访问的域名是什么？
- 如果用户认为连接可疑，能否临时提升观测等级？
- 能否进一步查看 TLS 元数据、HTTP 信息甚至应用层明文？

核心理念：

Low-overhead Always-on Observation
+
On-demand Deep Inspection
+
Adaptive Observation Levels

即：

默认进行低开销系统级网络行为观测。

只有目标进程或连接值得进一步分析时，才动态提高观测等级。

---

# 2. 核心设计原则

## 2.1 Process-centric

所有网络事件尽量关联到：

Process
→ Socket
→ Connection
→ Domain
→ TLS
→ HTTP

最终用户看到的不是：

1.2.3.4:443

而是：

python3
→ api.example.com
→ 1.2.3.4:443

---

## 2.2 Metadata First

默认情况下只记录 Metadata。

禁止默认抓取所有 TLS 明文或 HTTP Body。

系统常驻时优先保证：

- 低 CPU 开销
- 低内存占用
- 低事件量
- 不大量复制 Payload

---

## 2.3 On-demand Deep Inspection

用户可以对单个：

- Process
- PID
- Connection
- Domain

提升观测等级。

例如：

python3
→ suspicious.example
→ Upload 500 MB

用户点击：

Deep Inspect

然后系统动态加载更深层的 Probe。

---

## 2.4 Unified eBPF Instrumentation

eBPF Probe 尽量保持统一实现。

Probe 使用：

C
+
Clang/LLVM
+
eBPF Bytecode

运行时根据 Hook 类型选择：

Linux Kernel eBPF

或者：

bpftime

核心思想：

eBPF 是统一的 instrumentation program。

Kernel 和 bpftime 是不同 execution runtime。

---

# 3. 技术栈

## 3.1 eBPF

语言：

C

工具链：

- libbpf
- CO-RE
- clang
- bpftool
- BTF

---

## 3.2 用户态 Agent

语言：

Rust

职责：

- eBPF loader
- bpftime runtime control
- Process tracking
- Connection tracking
- DNS correlation
- TLS correlation
- Event correlation
- Observation level manager
- Detection engine
- Storage
- Local API
- UI backend

---

## 3.3 UI

推荐：

Tauri
+
TypeScript
+
React

也可以替换 React 为 Vue。

---

## 3.4 存储

第一阶段：

SQLite

---

## 3.5 事件传输

Kernel eBPF：

BPF Ring Buffer

bpftime：

使用 bpftime 提供的兼容 Event/Map 通道。

用户态统一转换为 TraceLens Event。

---

# 4. 总体架构

```text
                         TraceLens
                            │
                     Rust Security Agent
                            │
          ┌─────────────────┴──────────────────┐
          │                                    │
   Kernel eBPF Runtime                   bpftime Runtime
          │                                    │
          │                                    │
 Process / Network                    Userspace Deep Inspection
 DNS / Socket                         TLS / HTTP / Plaintext
 TCP / File                           Userspace Functions
          │                                    │
          └─────────────────┬──────────────────┘
                            │
                      Event Correlator
                            │
                   Observation Manager
                            │
                     Detection Engine
                            │
                         SQLite
                            │
                      Local API / IPC
                            │
                       Tauri Desktop
```

---

# 5. Runtime 分工

## Kernel eBPF

适合常驻系统级事件。

包括：

- exec
- fork
- clone
- exit
- connect
- accept
- TCP state
- UDP activity
- DNS
- socket
- network statistics
- file access
- process metadata

---

## bpftime

适合用户态动态深度观测。

例如：

- SSL_read
- SSL_write
- SSL_connect
- OpenSSL APIs
- BoringSSL APIs
- GnuTLS APIs
- application functions
- userspace USDT
- malloc/free
- custom userspace functions

第一阶段重点：

OpenSSL

---

# 6. eBPF Probe 目录

建议：

```text
bpf/
├── process.bpf.c
├── network.bpf.c
├── dns.bpf.c
├── tcp.bpf.c
├── file.bpf.c
├── tls.bpf.c
├── plaintext.bpf.c
└── common.bpf.h
```

---

# 7. Rust Agent 目录

建议：

```text
agent/
├── main.rs
│
├── runtime/
│   ├── mod.rs
│   ├── kernel.rs
│   ├── bpftime.rs
│   └── selector.rs
│
├── observation/
│   ├── manager.rs
│   ├── level.rs
│   └── target.rs
│
├── process/
│   ├── tracker.rs
│   └── model.rs
│
├── network/
│   ├── connection_tracker.rs
│   ├── socket_tracker.rs
│   └── model.rs
│
├── dns/
│   ├── tracker.rs
│   └── cache.rs
│
├── tls/
│   ├── tracker.rs
│   └── openssl.rs
│
├── http/
│   ├── parser.rs
│   └── stream.rs
│
├── events/
│   ├── model.rs
│   ├── correlator.rs
│   └── bus.rs
│
├── detection/
│   ├── engine.rs
│   ├── rules.rs
│   └── risk.rs
│
├── storage/
│   ├── sqlite.rs
│   └── schema.rs
│
└── api/
    ├── process.rs
    ├── connection.rs
    ├── alerts.rs
    └── observation.rs
```

---

# 8. Process Tracking

需要采集：

- PID
- TGID
- PPID
- UID
- GID
- comm
- executable path
- command line
- exec timestamp
- exit timestamp
- cgroup
- namespace

维护：

Process Tree

例如：

```text
systemd
└── sshd
    └── bash
        └── python3
```

---

# 9. Network Connection Tracking

支持：

- IPv4
- IPv6
- TCP
- UDP

TCP 第一阶段重点。

记录：

- PID
- TGID
- Process
- Executable
- Socket
- Source IP
- Source Port
- Destination IP
- Destination Port
- Protocol
- Start Time
- End Time
- State
- Upload Bytes
- Download Bytes

核心数据关系：

```text
Process
   ↓
Socket
   ↓
Connection
```

---

# 10. DNS Tracking

需要捕获：

- DNS Query
- DNS Response
- A
- AAAA

建立：

```text
Process
   ↓
Domain
   ↓
IP
```

记录：

- PID
- Domain
- IP
- TTL
- Query Time
- Response Time

DNS Cache 必须支持：

- TTL expiration
- 一个 IP 多域名
- 一个域名多 IP
- CDN
- DNS rotation

禁止简单实现：

IP → Domain 永久绑定

---

# 11. Domain Correlation

一个连接的域名可能来自：

1. DNS
2. TLS SNI
3. HTTP Host

内部模型应该保存多个 Evidence。

例如：

```text
Connection
IP = 104.x.x.x

DomainEvidence:
- DNS: api.example.com
- TLS SNI: api.example.com
- HTTP Host: api.example.com
```

可以计算 confidence。

---

# 12. Observation Levels

TraceLens 最核心功能之一。

定义：

## Level 0

No Observation

---

## Level 1

Basic Security Metadata

包含：

- Process
- Exec
- Fork
- Exit
- TCP Connection
- UDP Activity
- DNS
- Domain
- Upload
- Download
- Duration

默认全系统运行 L1。

---

## Level 2

Network Detail

增加：

- TCP State
- RTT
- Retransmission
- Socket Metadata
- TCP Metrics

---

## Level 3

TLS Metadata

增加：

- TLS SNI
- TLS Version
- ALPN
- Cipher Suite
- Certificate Metadata

优先使用 bpftime 用户态 Probe。

---

## Level 4

HTTP Metadata

增加：

- Method
- Host
- Path
- Status Code
- Headers
- Content-Type
- Content-Length

---

## Level 5

Deep Application Inspection

增加：

- TLS Plaintext
- HTTP Body
- WebSocket Payload
- Application Payload

Level 5 默认禁止全局开启。

---

# 13. Observation Target

Observation Level 必须支持针对：

```text
Global
Process
PID
Connection
Domain
```

例如：

```text
upgrade(
    target = PID 4821,
    level = 5
)
```

或者：

```text
upgrade(
    target = connection_id,
    level = 5
)
```

---

# 14. Observation Manager

Rust 用户态实现。

职责：

- 当前观测等级管理
- target 管理
- probe dependency resolution
- attach
- detach
- timeout
- reference count
- runtime selection

接口示例：

```text
upgrade(target, level)

downgrade(target, level)

stop(target)

get_level(target)
```

---

# 15. Probe Dependency

例如：

L1：

```text
process
network
dns
```

L3：

```text
L1
+
tls
```

L5：

```text
L3
+
plaintext
+
http
```

升级：

```text
L1 → L5
```

系统自动加载缺少的 Probe。

降级：

```text
L5 → L1
```

系统卸载：

- plaintext probe
- HTTP probe
- TLS probe

但保留：

- Process
- Network
- DNS

---

# 16. Runtime Selector

实现：

RuntimeSelector

根据 Probe 类型选择执行 Runtime。

例如：

```text
process_exec
→ Kernel

tcp_connect
→ Kernel

dns
→ Kernel

ssl_read
→ bpftime

ssl_write
→ bpftime
```

对于 userspace probe 可以配置：

```text
preferred_runtime = bpftime
fallback_runtime = kernel_uprobe
```

支持三种模式：

```text
Auto
Kernel
bpftime
```

默认：

Auto

---

# 17. Dynamic Deep Inspection

典型流程：

```text
python3
→ suspicious.example
→ Upload 300 MB
```

用户点击：

Deep Inspect

系统：

```text
Observation Manager

↓

PID 4821

↓

检测目标进程加载的 TLS Library

↓

发现 libssl.so

↓

选择 OpenSSL Probe

↓

Runtime Selector

↓

bpftime

↓

Attach SSL_read / SSL_write

↓

开始深度观测
```

---

# 18. TLS Library Detection

用户态 Agent 需要检查：

```text
/proc/<pid>/maps
```

识别：

- libssl
- BoringSSL
- GnuTLS
- NSS
- Rustls
- Go executable

第一阶段只实现：

OpenSSL

---

# 19. OpenSSL TLS Metadata

第一阶段支持：

- SSL_connect
- SSL_accept
- SSL_get_servername
- SSL_get_version
- SSL_get_current_cipher

或者通过 OpenSSL 内部对象读取相关信息。

记录：

- PID
- SSL pointer
- SNI
- TLS version
- cipher
- ALPN
- connection ID

核心映射：

```text
SSL Object
   ↓
Process
   ↓
Socket
   ↓
Connection
```

---

# 20. TLS Plaintext

通过：

```text
SSL_read
SSL_write
```

获取：

Inbound Plaintext

Outbound Plaintext

需要保存：

- PID
- TID
- SSL pointer
- direction
- timestamp
- payload
- length

---

# 21. Plaintext Correlation

不能简单按 PID 关联。

应该尽量使用：

```text
PID
+
SSL Object
+
Socket
+
Connection
```

建立映射。

数据流：

```text
SSL_write()
↓

SSL*
↓

fd

↓

Socket

↓

Connection
```

---

# 22. HTTP/1.1 Parsing

第一阶段只支持 HTTP/1.1。

Level 4：

解析：

- Method
- Host
- Path
- Status
- Headers
- Content-Type
- Content-Length

Level 5：

进一步保存：

- Request Body
- Response Body

---

# 23. Stream Reassembly

必须考虑：

一个：

SSL_read

不等于：

一个 HTTP Response。

例如：

```text
SSL_read #1
HTTP Header Part 1

SSL_read #2
Header Part 2

SSL_read #3
Body
```

因此 Agent 需要：

Connection Stream Buffer

按照：

```text
Connection
+
Direction
```

重组。

---

# 24. HTTP/2 / HTTP/3

第一版不要求。

后续：

HTTP/2：

- frame parsing
- HPACK
- stream ID

HTTP/3：

- QUIC
- HTTP/3 frames
- QPACK

---

# 25. Process Timeline

每个 Process 建立统一 Timeline。

例如：

```text
14:03:21 exec /tmp/a.out
14:03:21 DNS evil.example
14:03:22 connect 45.x.x.x:443
14:03:23 TLS SNI evil.example
14:03:25 read ~/.ssh/id_rsa
14:03:26 upload 18 KB
14:03:30 exit
```

Timeline 是重要 UI。

---

# 26. Connection Timeline

每条连接：

```text
DNS
↓

Connect

↓

TLS Handshake

↓

HTTP Request

↓

Upload / Download

↓

Close
```

---

# 27. File Security Context

TraceLens 主体依然偏网络安全。

File Monitoring 主要用于给网络行为增加上下文。

第一阶段监控：

- open
- read
- write
- rename
- unlink

重点标记：

```text
~/.ssh
/etc
/tmp
/var/tmp
credentials
keys
tokens
```

例如：

```text
python3
↓

read ~/.ssh/id_rsa

↓

connect suspicious.example

↓

upload 20 KB
```

---

# 28. Detection Engine

第一阶段使用 Rule-based Detection。

不做机器学习。

---

# 29. Detection Rules

至少支持：

## Rule 1

新进程立即访问网络。

---

## Rule 2

/tmp 或 /var/tmp 中 executable 启动后访问公网。

---

## Rule 3

单进程短时间访问大量不同 IP。

---

## Rule 4

单进程扫描大量端口。

---

## Rule 5

内网横向扫描。

---

## Rule 6

稳定周期连接。

可能为：

C2 Beacon。

---

## Rule 7

大量上传。

---

## Rule 8

Upload / Download ratio 异常。

---

## Rule 9

读取敏感文件后访问公网。

---

## Rule 10

读取敏感文件后发生上传。

---

## Rule 11

首次访问未知域名。

---

## Rule 12

首次访问未知公网 IP。

---

# 30. Beacon Detection

维护连接时间序列：

```text
59.8s
60.1s
60.0s
59.9s
```

计算：

- mean interval
- variance
- jitter

如果周期稳定：

```text
Possible C2 Beacon
```

记录：

- PID
- Domain
- IP
- Period
- Jitter
- Count

---

# 31. Port Scan Detection

例如：

```text
python3

10.0.0.1:22
10.0.0.1:23
10.0.0.1:80
10.0.0.1:443
...
```

判断：

Possible Port Scan

---

# 32. Lateral Movement Detection

例如：

```text
10.0.0.10:22
10.0.0.11:22
10.0.0.12:22
10.0.0.13:22
```

判断：

Possible Lateral Movement

---

# 33. Data Exfiltration Detection

关联：

```text
Sensitive File Read

↓

External Connection

↓

Large Upload
```

输出高风险 Alert。

---

# 34. First-seen Database

维护：

- First Seen Process
- First Seen Executable
- First Seen Domain
- First Seen IP
- First Seen Port

用于异常判断。

---

# 35. Risk Score

Process 和 Connection 都可以有：

Risk Score

范围：

0 - 100

例如：

```text
python3
Risk 86
```

原因：

```text
+20 Executed from /tmp
+20 First-seen executable
+15 New domain
+20 Sensitive file read
+20 Large upload
-9 Known trusted destination
```

第一阶段可以简单线性规则。

---

# 36. Alert Model

Alert：

```text
id
timestamp
severity
type
process_id
connection_id
title
description
evidence
risk_score
```

Severity：

```text
Info
Low
Medium
High
Critical
```

---

# 37. UI 总体结构

侧边栏：

```text
Dashboard

Processes

Connections

Alerts

Timeline

Behavior Graph

Settings
```

---

# 38. Dashboard

显示：

- Active Processes
- Active Connections
- Network Upload
- Network Download
- New Domains
- Suspicious Processes
- Active Deep Inspections
- Alerts

---

# 39. Process View

表格：

```text
Process
PID
User
Connections
Domains
Upload
Download
Risk
Observation Level
```

支持：

- 搜索
- 排序
- Filter
- Risk filter
- Observation Level filter

---

# 40. Process Detail

Tabs：

```text
Overview
Connections
DNS
Files
Timeline
Alerts
```

如果 Level >= 3：

增加：

```text
TLS
```

Level >= 4：

增加：

```text
HTTP
```

Level >= 5：

增加：

```text
Plaintext
```

---

# 41. Connection View

列表：

```text
Process
Domain
IP
Port
Protocol
Upload
Download
Duration
TLS
Risk
Observation Level
```

---

# 42. Connection Detail

显示：

```text
Process

Destination

Domain

IP

Port

Start Time

Duration

Traffic

DNS Evidence

TLS

HTTP

Timeline

Alerts
```

---

# 43. Observation Level UI

每个 Process / Connection 显示：

```text
Observation Level

L1 L2 L3 L4 L5
```

支持按钮：

```text
Upgrade Observation

Deep Inspect

Downgrade

Stop Inspection
```

---

# 44. Deep Inspect UI

用户点击：

```text
Deep Inspect
```

弹出：

```text
Target:
python3 PID 4821

Current Level:
L1

Target Level:
L5

Runtime:
Auto

Duration:
5 min

[Start Inspection]
```

---

# 45. Active Inspection

显示：

```text
Deep Inspection Active

PID 4821

Level L5

Runtime bpftime

TLS Provider OpenSSL

Remaining 04:32
```

---

# 46. Plaintext View

例如：

```text
OUTBOUND

POST /api/upload HTTP/1.1
Host: suspicious.example
Content-Type: application/json

...

INBOUND

HTTP/1.1 200 OK
Content-Type: application/json

...
```

需要支持：

- Direction filter
- Search
- Timestamp
- Hex View
- Text View

---

# 47. Behavior Graph

主要展示：

```text
Process
├── Child Process
├── Domain
├── IP
├── Connection
└── File
```

例如：

```text
bash
 ↓
python3
 ├── ~/.ssh/id_rsa
 ├── evil.example
 │      ↓
 │   45.x.x.x
 │
 └── api.example.com
```

---

# 48. 数据模型

核心 Entity：

```text
Process

Socket

Connection

Domain

DNSRecord

TLSConnection

HTTPTransaction

FileEvent

Alert

ObservationSession
```

---

# 49. Connection Model 示例

```text
Connection {
    id

    pid
    process_id

    protocol

    source_ip
    source_port

    destination_ip
    destination_port

    domain

    start_time
    end_time

    upload_bytes
    download_bytes

    observation_level

    risk_score
}
```

---

# 50. Unified Event Model

所有 Probe Event 最终转换成：

```text
TraceEvent {
    timestamp

    event_type

    pid
    tid

    process_id

    connection_id

    payload
}
```

event_type：

```text
ProcessExec
ProcessExit

Connect
Accept
Close

DNSQuery
DNSResponse

TLSHandshake

SSLRead
SSLWrite

HTTPRequest
HTTPResponse

FileOpen
FileRead

Alert
```

---

# 51. Event Correlation

Event Correlator 是 Agent 核心。

负责建立：

```text
PID
↕
Process

Socket
↕

Connection

↕

Domain

↕

TLS Object

↕

HTTP Stream
```

---

# 52. SQLite Schema

第一阶段至少：

```text
processes

connections

dns_records

domains

tls_sessions

http_requests

file_events

alerts

timeline_events

observation_sessions
```

---

# 53. Plaintext Storage Policy

默认：

Plaintext 不长期持久化。

策略：

- Memory only
- Ring buffer
- Max size
- Max retention
- Per session
- User clear

例如：

默认：

5 分钟

或者：

50 MB

超过自动清理。

---

# 54. Security / Privacy

因为 TraceLens 可以查看 TLS 明文，因此必须明确：

- 默认关闭
- 必须用户主动 Deep Inspect
- 针对指定目标
- 有明确 Active Inspection 状态
- 自动超时
- Plaintext 默认不持久化

---

# 55. Capability Check

启动时检查：

- Kernel BTF
- BPF support
- ringbuf support
- CAP_BPF
- CAP_PERFMON
- CAP_SYS_ADMIN
- uprobe support
- bpftime availability
- bpftime runtime status

---

# 56. Compatibility

MVP：

Linux x86_64

随后：

Linux ARM64

优先支持：

Ubuntu

随后：

Debian
Fedora
Arch

---

# 57. bpftime Availability

如果 bpftime 不可用：

TraceLens 仍可以运行。

状态：

```text
Kernel Observation: Available

Deep Inspection Runtime:
bpftime unavailable
```

可以 fallback：

Kernel uprobe

---

# 58. Runtime Fallback

对于 OpenSSL：

优先：

```text
bpftime
```

失败：

```text
kernel uprobe
```

再失败：

```text
Deep Inspection unavailable
```

---

# 59. Logging

Rust Agent 使用结构化日志。

等级：

```text
error
warn
info
debug
trace
```

禁止在生产默认大量输出每个网络事件。

---

# 60. Configuration

配置文件：

```text
tracelens.toml
```

例如：

```text
[observation]

default_level = 1

deep_inspection_timeout = 300

preferred_userspace_runtime = "bpftime"

[storage]

database = "tracelens.db"

plaintext_storage = "memory"

plaintext_max_mb = 50
```

---

# 61. MVP 范围

第一版必须完成：

## Kernel

- Process exec
- Process exit
- TCP connect
- TCP close
- IPv4
- IPv6
- Upload / Download
- DNS Query
- DNS Response

---

## Correlation

- Process → Connection
- Domain → IP
- Connection → Domain
- Process Timeline

---

## UI

- Dashboard
- Processes
- Process Detail
- Connections
- Connection Detail
- Timeline
- Observation Level

---

## Deep Inspection

支持：

Linux
+
OpenSSL
+
bpftime

能力：

- TLS SNI
- TLS Version
- SSL_read
- SSL_write
- TLS Plaintext

---

## Observation Level

MVP 先实现：

```text
L1
L3
L5
```

L2 / L4 可以后补。

---

# 62. MVP 暂不实现

暂时不要实现：

- HTTP/2
- HTTP/3
- QUIC
- BoringSSL
- GnuTLS
- NSS
- Go TLS
- Java TLS
- Rustls
- Threat Intelligence
- VirusTotal
- GeoIP
- Cloud Backend
- Account System
- Machine Learning
- Remote Agent
- Multi-host Dashboard

---

# 63. 开发阶段

## Phase 1：项目骨架

完成：

- Repository
- CMake / Cargo
- libbpf build
- Rust workspace
- Tauri UI
- shared event structs

---

## Phase 2：Process Tracking

完成：

- exec
- exit
- Process Tree
- Process UI

---

## Phase 3：Connection Tracking

完成：

- TCP connect
- close
- IPv4
- IPv6
- PID association
- upload/download
- Connection UI

---

## Phase 4：DNS

完成：

- DNS query
- response
- domain cache
- connection correlation

最终 UI：

```text
python
→ api.example.com:443
```

---

## Phase 5：Timeline

统一：

Process
+
Network
+
DNS

事件 Timeline。

---

## Phase 6：Observation Manager

实现：

```text
L1

upgrade

downgrade

timeout
```

---

## Phase 7：bpftime Integration

实现：

- detect bpftime
- runtime interface
- attach userspace eBPF
- detach
- runtime fallback

---

## Phase 8：OpenSSL Metadata

实现：

- libssl detection
- TLS SNI
- TLS version
- connection correlation

完成：

L3

---

## Phase 9：TLS Plaintext

实现：

- SSL_read
- SSL_write
- buffer collection
- SSL object correlation
- plaintext UI

完成：

L5

---

## Phase 10：HTTP/1.1

实现：

- stream reassembly
- request parser
- response parser
- method
- host
- path
- status
- headers

---

## Phase 11：Detection

实现：

- beacon
- scan
- lateral movement
- suspicious upload
- new domain
- sensitive file + network correlation

---

## Phase 12：Behavior Graph

加入：

Process
Domain
Connection
File

关系图。

---

# 64. 第一阶段成功标准

运行 TraceLens 后：

用户打开任意网络程序。

例如：

```text
curl https://example.com
```

TraceLens UI 能显示：

```text
curl

PID 12345

example.com

93.184.216.34:443

Connected

Upload

Download
```

---

然后：

用户点击：

```text
Deep Inspect
```

TraceLens：

```text
L1 → L5
```

自动：

```text
检测 libssl

↓

bpftime attach

↓

SSL_read / SSL_write
```

UI 开始出现 TLS Plaintext。

---

停止 Deep Inspect：

```text
L5 → L1
```

bpftime Probe 被卸载。

系统继续只进行低开销 Metadata 观测。

---

# 65. 最终用户体验

正常状态：

```text
TraceLens

Processes
────────────────────────────

chrome        48 connections
curl           1 connection
python3         3 connections
sshd            2 connections
```

用户发现：

```text
python3

suspicious.example

Upload 500 MB
```

点击：

```text
Deep Inspect
```

TraceLens：

```text
Observation

L1 → L5

Runtime:

bpftime

TLS:

OpenSSL
```

随后看到：

```text
POST /upload HTTP/1.1

Host: suspicious.example

Content-Type: application/octet-stream
```

分析结束：

```text
Stop Inspection
```

系统：

```text
detach userspace probes

↓

L5 → L1
```

---

# 66. TraceLens 核心差异

TraceLens 不是：

tcpdump

因为 tcpdump 是 Packet-centric。

TraceLens 也不是：

nethogs

因为 nethogs 主要关注带宽。

TraceLens 也不是完整传统 EDR。

TraceLens 的核心是：

```text
Process-aware

+

Network Security Observation

+

Dynamic Deep Inspection
```

即：

```text
Process

↓

Connection

↓

Domain

↓

TLS

↓

HTTP

↓

Plaintext
```

---

# 67. 项目核心理念

TraceLens 的目标不是默认收集最多的数据。

而是：

默认只观察行为轮廓。

当一个目标值得关注时，再逐步提高观察倍率。

类似显微镜：

```text
Overview

↓

Focus

↓

Zoom

↓

Deep Inspection
```

因此：

TraceLens

中的：

Lens

就是整个产品交互理念的一部分。

核心一句话：

TraceLens continuously observes system-wide process network behavior with low overhead, and dynamically escalates selected processes or connections into deep userspace inspection using eBPF and bpftime.