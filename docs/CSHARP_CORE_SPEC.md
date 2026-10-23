# MuClip Core (`muclip-core`)

> **高性能、轻量级、跨平台的局域网 P2P 剪贴板同步与高速加密流式文件传输核心引擎。**
> 
> 本文档专为后续 **Windows 客户端（C# / .NET 8 / WPF / WinUI 3 / Avalonia）** 及其他原生平台的接入开发者编写，涵盖核心架构、Windows DLL 编译指南、C ABI 导出规范、内存生命周期管理最佳实践以及**开箱即用的完整 C# 封装代码库**。

---

## 目录

- [1. 架构概述与核心特性](#1-架构概述与核心特性)
- [2. Windows 平台编译与集成](#2-windows-平台编译与集成)
- [3. C ABI 导出函数全量规范](#3-c-abi-导出函数全量规范)
  - [3.1 内存释放与版本信息](#31-内存释放与版本信息)
  - [3.2 引擎生命周期与 SQLite 历史记录 CRUD](#32-引擎生命周期与-sqlite-历史记录-crud)
  - [3.3 常用语 (Phrases) 模板管理](#33-常用语-phrases-模板管理)
  - [3.4 内容特征分析与单行预览](#34-内容特征分析与单行预览)
  - [3.5 租借式高性能内存池 (Zero-Copy Memory Pool)](#35-租借式高性能内存池-zero-copy-memory-pool)
  - [3.6 P2P 局域网同步引擎 (自发现、广播、监听)](#36-p2p-局域网同步引擎-自发现广播监听)
  - [3.7 安全配对机制 (PIN 握手、白名单、双向解绑拦截)](#37-安全配对机制-pin-握手白名单双向解绑拦截)
  - [3.8 高性能加密流式文件传输 (100MB/s+、分块校验、进度统计)](#38-高性能加密流式文件传输-100mbs分块校验进度统计)
- [4. C# (.NET / Windows) 接入核心规范与避坑指南](#4-c-net--windows-接入核心规范与避坑指南)
  - [4.1 黄金法则一：Native 字符串内存管理与释放](#41-黄金法则一native-字符串内存管理与释放)
  - [4.2 黄金法则二：回调委托防 GC 回收 (Delegate GC Pinning)](#42-黄金法则二回调委托防-gc-回收-delegate-gc-pinning)
  - [4.3 黄金法则三：结构体固定缓冲区编组](#43-黄金法则三结构体固定缓冲区编组)
- [5. C# 开箱即用完整封装代码库 (Ready-to-use Wrapper)](#5-c-开箱即用完整封装代码库-ready-to-use-wrapper)
  - [5.1 NativeMethods.cs (全量 P/Invoke 声明)](#51-nativemethodscs-全量-pinvoke-声明)
  - [5.2 DataModels.cs (强类型 DTO 实体)](#52-datamodelscs-强类型-dto-实体)
  - [5.3 MuClipCoreService.cs (高层单例服务与事件驱动)](#53-muclipcoreservicecs-高层单例服务与事件驱动)
- [6. C# 快速接入示例 (Quick Start)](#6-c-快速接入示例-quick-start)

---

## 1. 架构概述与核心特性

`muclip-core` 是 MuClip 跨平台产品矩阵的核心底座，使用纯 Rust 编写并直接编译为 C-ABI 动态链接库（Windows 下为 `muclip_core.dll`，Android 下为 `libmuclip_core.so`），具备极致的运行速度、内存安全与零外部重量级运行依赖。

```
                    ┌──────────────────────────────────────────────┐
                    │   Windows Client (.NET 8 / C# WPF / WinUI)   │
                    │   Android Client (Kotlin Jetpack Compose)    │
                    └───────────────────────┬──────────────────────┘
                                            │ P/Invoke / JNI
                                            ▼
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│                                   muclip-core (Rust)                                     │
├───────────────────┬───────────────────┬───────────────────┬──────────────────────────────┤
│    FFI Layer      │   Sync Engine     │   File Transfer   │       Storage & Memory       │
│  - C ABI Exports  │  - mDNS / UDP     │  - 128KB Chunking │  - Bundled SQLite 3          │
│  - JNI Direct     │  - TCP_NODELAY    │  - SHA-256 Check  │  - LRU Memory Cache          │
│  - Leased Pool    │  - XChaCha20-Poly │  - Real-time bps  │  - Off-heap Buffer Pool      │
│  - String SafeDrop│  - Bilateral Pair │  - CancellationToken│ - Content Auto-Classifier  │
└───────────────────┴───────────────────┴───────────────────┴──────────────────────────────┘
```

### 核心特性
1. **高性能流式文件传输**：
   - 采用 128KB 黄金分块切片 + `TCP_NODELAY` 零缓冲直发。
   - 硬件加速 XChaCha20-Poly1305 流式分块加密与 SHA-256 完整性哈希校验。
   - 实测局域网吞吐量达 **100MB/s ~ 110MB/s**（跑满千兆网卡/Wi-Fi 6），提供实时进度、瞬时速度与双向随时取消支持。
2. **多网卡穿透自发现 (P2P Discovery)**：
   - mDNS 5353 组播 + UDP 42110 子网定向广播双频并发。
   - 自动枚举 Windows 宿主机所有活动物理与虚拟网卡（适配多网卡、虚拟交换机、VPN 复杂网络）。
   - 收到对端信标后触发单播反向 Ping-Pong 回应，告别单向组播丢包，实现秒级无感互联。
3. **严格单向 PIN 配对与双向解绑拦截**：
   - 支持设置独立配对 PIN 码，单流 TCP 握手验证，杜绝局域网旁路窃听。
   - 一旦任意一端主动解除配对，后续同步数据包将立即被对端拦截并返回错误码，本地自动联动移除配对状态。
4. **LRU 内存热缓存与内置 SQLite**：
   - 核心自带静态编译的 SQLite 引擎，剪贴板历史记录自动去重（Upsert）、支持全文模糊搜索与过期自动清理。
   - 顶层叠加 LRU 内存热缓存（100 条 / 5MB 上限），退出自动回写，极致降低磁盘 I/O。
5. **租借式零拷贝内存池 (Leased Memory Pool)**：
   - 原生堆外内存复用机制（`muclip_pool_acquire` / `muclip_pool_release`），大文本和历史数据直写内存池，降低 GC 压力与碎片。

---

## 2. Windows 平台编译与集成

### 2.1 编译环境准备
- **Rust 工具链**：1.80+ (推荐 `stable-x86_64-pc-windows-msvc`)
- **构建工具**：Visual Studio 2022 C++ 生成工具或 Visual Studio Community。

### 2.2 编译生成 `muclip_core.dll`
在仓库根目录下执行：

```powershell
# 编译 Release 优化版本 (带 LTO 和符号剥离)
cargo build --release
```

编译完成后，产物位于：
- **动态链接库**：`target/release/muclip_core.dll` (~2.4 MB)
- **导入库**：`target/release/deps/muclip_core.dll.lib`

> [!TIP]
> `muclip-core` 已配置 `rusqlite` 的 `bundled` 特性，SQLite 源码已被纯静态链接进 DLL，目标机上**无需安装任何外部 C++ 运行库或 SQLite.dll**。

### 2.3 C# 项目集成工程配置
在 C# 的 `.csproj` 项目文件中配置，让编译时自动拷贝 DLL 至运行目录：

```xml
<ItemGroup>
  <None Include="..\..\target\release\muclip_core.dll">
    <CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory>
    <Visible>false</Visible>
  </None>
</ItemGroup>
```

---

## 3. C ABI 导出函数全量规范

所有导出函数遵循标准 C 调用约定（`extern "C"`，在 Windows x64 下自动适配标准 x64 调用约定）。函数定义位于 [`src/ffi/exports/`](../src/ffi/exports/)。

### 3.1 内存释放与版本信息

#### `muclip_core_free_string`
```c
void muclip_core_free_string(char* s);
```
- **功能**：释放由 Rust 分配并返回给外部调用者的堆内存字符串（`*mut c_char`）。
- **注意**：**所有返回 `char*` 的 `muclip_*` 函数产物在 C# 读取后必须调用此函数释放，绝对严禁使用 .NET 的 `Marshal.FreeHGlobal` 或 `CoTaskMemFree`！**

#### `muclip_core_version`
```c
char* muclip_core_version(void);
```
- **功能**：获取核心库语义化版本号（如 `"0.1.0"`）。需调用 `muclip_core_free_string` 释放。

---

### 3.2 引擎生命周期与 SQLite 历史记录 CRUD

#### `muclip_core_new`
```c
MuClipCoreHandle* muclip_core_new(const char* db_path);
```
- **功能**：根据 SQLite 文件路径初始化核心引擎句柄，自动执行建表并预热加载最近历史记录至 LRU 缓存。
- **返回**：引擎不透明指针句柄，失败返回 `NULL`。

#### `muclip_core_new_in_memory`
```c
MuClipCoreHandle* muclip_core_new_in_memory(void);
```
- **功能**：创建纯内存模式的引擎（适合单元测试或无痕会话）。

#### `muclip_core_free`
```c
void muclip_core_free(MuClipCoreHandle* handle);
```
- **功能**：释放引擎句柄，并将内存缓存中未回写的数据强制刷盘至 SQLite。

#### `muclip_core_add_history`
```c
int64_t muclip_core_add_history(MuClipCoreHandle* handle, const char* content);
```
- **功能**：添加一条剪贴板文本记录。如果内容重复则更新其 `last_used_at`。
- **返回**：记录 ID，失败返回 `-1`。

#### `muclip_core_query_history`
```c
char* muclip_core_query_history(MuClipCoreHandle* handle, size_t limit);
```
- **功能**：按最后使用时间降序获取最近历史记录。
- **返回**：`HistoryItem[]` 的 UTF-8 JSON 字符串，需调用 `muclip_core_free_string` 释放。

#### `muclip_core_search_history`
```c
char* muclip_core_search_history(MuClipCoreHandle* handle, const char* query, size_t limit);
```
- **功能**：根据关键字全文模糊搜索剪贴板历史。
- **返回**：`HistoryItem[]` 的 UTF-8 JSON 字符串，需释放。

#### `muclip_core_delete_history`
```c
int32_t muclip_core_delete_history(MuClipCoreHandle* handle, int64_t id);
```
- **功能**：根据 ID 删除单条历史记录。成功返回 `0`，失败返回 `-1`。

#### `muclip_core_clear_history`
```c
int32_t muclip_core_clear_history(MuClipCoreHandle* handle);
```
- **功能**：清空所有历史记录。成功返回 `0`，失败返回 `-1`。

#### `muclip_core_cleanup_history`
```c
int32_t muclip_core_cleanup_history(MuClipCoreHandle* handle, uint32_t days);
```
- **功能**：自动清理保留天数大于 `days` 的旧历史数据。返回被删除的条数，失败返回 `-1`。

#### `muclip_core_get_cached_items`
```c
char* muclip_core_get_cached_items(MuClipCoreHandle* handle);
```
- **功能**：快速读取热数据 LRU 内存缓存（零 SQLite I/O 损耗）。返回 JSON 数组，需释放。

---

### 3.3 常用语 (Phrases) 模板管理

#### `muclip_core_add_phrase`
```c
int64_t muclip_core_add_phrase(MuClipCoreHandle* handle, const char* content);
```
- **功能**：添加一条预设常用短语。返回短语 ID，失败返回 `-1`。

#### `muclip_core_edit_phrase`
```c
int32_t muclip_core_edit_phrase(MuClipCoreHandle* handle, int64_t id, const char* new_content);
```
- **功能**：修改指定常用短语。成功返回 `0`，失败返回 `-1`。

#### `muclip_core_delete_phrase`
```c
int32_t muclip_core_delete_phrase(MuClipCoreHandle* handle, int64_t id);
```
- **功能**：删除指定常用短语。成功返回 `0`，失败返回 `-1`。

#### `muclip_core_update_phrase_used`
```c
int32_t muclip_core_update_phrase_used(MuClipCoreHandle* handle, int64_t id);
```
- **功能**：更新短语使用时间（提升权重）。成功返回 `0`，失败返回 `-1`。

#### `muclip_core_query_phrases` / `muclip_core_search_phrases`
```c
char* muclip_core_query_phrases(MuClipCoreHandle* handle);
char* muclip_core_search_phrases(MuClipCoreHandle* handle, const char* query);
```
- **功能**：获取全部常用语 / 搜索常用语。返回 `PhraseItem[]` JSON 字符串，需释放。

---

### 3.4 内容特征分析与单行预览

#### `muclip_core_format_preview`
```c
char* muclip_core_format_preview(const char* text, size_t max_chars);
```
- **功能**：将多行或超长文本格式化为单行缩略文本（截断并追加 `...`）。需释放。

#### `muclip_core_analyze_content`
```c
char* muclip_core_analyze_content(const char* text);
```
- **功能**：智能分析文本类型（`plain_text`, `url`, `email`, `hex_color`, `json`, `code`, `number`），并统计字符数、行数、字节数。
- **返回**：`ContentAnalysis` JSON 字符串，需释放。

---

### 3.5 租借式零拷贝二进制内存池 (Zero-Copy Binary Memory Pool)

适用于极高吞吐、零 JSON 序列化损耗与零 GC 停顿场景。Rust 直接将小端序（Little-Endian）紧凑二进制线格式写入原生内存池，C# 侧通过 `unsafe` 指针包装为 `ReadOnlySpan<byte>` + `BinaryPrimitives` 直接读取，并在 `finally` 中调用 `muclip_pool_release(lease_id)` 归还租借：
- `muclip_pool_acquire(min_capacity, out_ptr, out_cap) -> u64`：从原生池租借一块内存，返回 `lease_id`。
- `muclip_pool_release(lease_id) -> i32`：将内存归还给原生池（**谁分配，谁释放**）。
- `muclip_pool_clear()`：清空原生池缓存。
- `muclip_core_query_history_pooled(handle, limit, out_ptr, out_len) -> u64`：直接将 `HistoryItem[]` 二进制流写入租借内存。
- `muclip_core_get_cached_items_pooled(handle, out_ptr, out_len) -> u64`：直接将 LRU 热缓存 `HistoryItem[]` 二进制流写入租借内存。
- `muclip_core_search_history_pooled(handle, query, limit, out_ptr, out_len) -> u64`：直接将搜索结果 `HistoryItem[]` 二进制流写入租借内存。
- `muclip_core_query_phrases_pooled(handle, out_ptr, out_len) -> u64` / `muclip_core_search_phrases_pooled(handle, query, out_ptr, out_len) -> u64`：直接将 `PhraseItem[]` 二进制流写入租借内存。
- `muclip_core_analyze_content_pooled(text, out_ptr, out_len) -> u64`：直接将 `ContentAnalysis` 二进制流写入租借内存。
- `muclip_sync_get_active_peers_pooled(handle, out_ptr, out_len) -> u64` / `muclip_sync_get_all_peers_pooled(handle, out_ptr, out_len) -> u64`：直接将 `PeerInfo[]` 二进制流写入租借内存。
- `muclip_sync_get_manual_peers_pooled(handle, out_ptr, out_len) -> u64`：直接将外部端口映射节点列表 `string[]` 二进制流写入租借内存。

---

### 3.6 P2P 局域网同步引擎 (自发现、广播、监听)

#### 回调函数定义
```c
typedef void (*MuClipClipboardCallback)(
    const char* content,
    const char* content_type,
    const char* device_id,
    const char* device_name,
    void* user_data
);
```

#### `muclip_sync_start`
```c
MuClipSyncHandle* muclip_sync_start(
    const char* device_id,
    const char* device_name,
    const char* device_type,
    uint16_t sync_port,       // TCP 同步端口，填 0 默认 42424
    uint16_t discovery_port,  // UDP 发现端口，填 0 默认 42110
    const char* pairing_pin   // 初始配对 PIN 码，无则传 ""
);
```
- **功能**：启动后台同步服务器、mDNS/UDP 自发现广播与监听线程。

#### `muclip_sync_stop`
```c
void muclip_sync_stop(MuClipSyncHandle* handle);
```
- **功能**：停止所有后台线程并释放同步引擎。

#### `muclip_sync_get_bound_port`
```c
uint16_t muclip_sync_get_bound_port(MuClipSyncHandle* handle);
```
- **功能**：获取 TCP 服务端实际成功绑定的端口号。

#### `muclip_sync_get_active_peers_pooled` / `muclip_sync_get_all_peers_pooled`
```c
uint64_t muclip_sync_get_active_peers_pooled(MuClipSyncHandle* handle, const uint8_t** out_ptr, size_t* out_len);
uint64_t muclip_sync_get_all_peers_pooled(MuClipSyncHandle* handle, const uint8_t** out_ptr, size_t* out_len);
```
- **功能**：获取局域网内当前在线设备 / 所有已知设备（含端口映射节点）的 Little-Endian 二进制缓冲，返回 `lease_id`，读取完毕后调用 `muclip_pool_release(lease_id)` 归还。

#### `muclip_sync_broadcast`
```c
size_t muclip_sync_broadcast(MuClipSyncHandle* handle, const char* text, const char* content_type);
```
- **功能**：将本地剪贴板内容推送给所有已配对且在线的对端设备。引擎内置环路回显抑制（Loopback Filter），防止对端回弹死循环。
- **返回**：成功发送的设备数量。

#### `muclip_sync_set_callback`
```c
void muclip_sync_set_callback(
    MuClipSyncHandle* handle,
    MuClipClipboardCallback callback,
    void* user_data
);
```
- **功能**：注册接收远端设备剪贴板推送的回调函数。

#### `muclip_sync_set_auto_discovery` / `muclip_sync_trigger_scan`
```c
int32_t muclip_sync_set_auto_discovery(MuClipSyncHandle* handle, int32_t enabled);
int32_t muclip_sync_trigger_scan(MuClipSyncHandle* handle);
```
- **功能**：控制是否开启后台定期心跳探测广播；`trigger_scan` 可立即触发一次全网卡穿透扫描。

---

### 3.7 安全配对机制 (PIN 握手、白名单、双向解绑拦截)

#### 配对结果结构体 (`MuClipPairResult`)
```c
typedef struct {
    int32_t success;                 // 0=成功, 1=对端拒绝, 2=PIN码错误, 3=超时, -1=网络或内部错误
    uint8_t responder_device_id[128];   // UTF-8 零结尾字符串
    uint8_t responder_device_name[128]; // UTF-8 零结尾字符串
    uint8_t error_message[256];        // 错误提示文本
    uint8_t long_term_key[65];         // ECDH 协商生成的 64 字符十六进制长期密钥
} MuClipPairResult;
```

#### 配对相关回调
```c
// 收到对端发来的配对请求弹窗通知
typedef void (*MuClipPairRequestCallback)(
    const char* request_id,
    const char* device_id,
    const char* device_name,
    const char* peer_ip,
    void* user_data
);

// 配对成功通知
typedef void (*MuClipPairSuccessCallback)(
    const char* device_id,
    const char* device_name,
    const char* peer_ip,
    const char* pin,
    void* user_data
);
```

#### `muclip_sync_request_pair`
```c
int32_t muclip_sync_request_pair(
    MuClipSyncHandle* handle,
    const char* peer_addr,   // 对端 IP:Port，例如 "192.168.1.102:42424"
    const char* pin,         // 用户输入的对方 PIN 码
    uint32_t timeout_secs,   // 超时时间（秒），传 0 默认 60s
    MuClipPairResult* out_result
);
```
- **功能**：主动向对端设备发起单连接 TCP 握手配对。若对端接受，本地将自动将对端加入配对白名单并保存 PIN 码。

#### `muclip_sync_respond_pair`
```c
int32_t muclip_sync_respond_pair(
    MuClipSyncHandle* handle,
    const char* request_id,
    const char* pin,
    int32_t accept           // 1=同意, 0=拒绝
);
```
- **功能**：用户在弹窗点击确认/拒绝后，向发起端返回握手结果。

#### `muclip_sync_remove_paired_device`
```c
int32_t muclip_sync_remove_paired_device(MuClipSyncHandle* handle, const char* device_id);
```
- **功能**：解除与指定设备的配对关系，并**自动向对端发送解配通告**。后续对端若未解配并尝试发来剪贴板内容，将被安全拦截（返回 `NotPairedByPeer`），对端也会联动取消配对。

---

### 3.8 高性能加密流式文件传输 (100MB/s+、分块校验、进度统计)

#### 文件传输回调函数定义
```c
// 传输进度回调 (发送端与接收端均触发)
typedef void (*MuClipFileProgressCallback)(
    const char* transfer_id,
    uint64_t transferred_bytes,
    uint64_t total_bytes,
    uint64_t speed_bps,       // 瞬时传输速率 (字节/秒)，乘以 8 为比特率
    int32_t is_send,          // 1=本地发送中, 0=本地接收中
    void* user_data
);

// 传输结束回调
typedef void (*MuClipFileCompletedCallback)(
    const char* transfer_id,
    const char* file_path,    // 发送的文件源路径 或 接收端保存的完整本地路径
    int32_t is_send,
    int32_t success,          // 1=成功完成, 0=失败或被取消
    const char* error_msg,    // 错误信息（若成功则为空串）
    void* user_data
);

// 收到对端传来的文件要约通知
typedef void (*MuClipFileOfferCallback)(
    const char* transfer_id,
    const char* from_device_id,
    const char* from_device_name,
    const char* file_name,
    uint64_t file_size,
    void* user_data
);
```

#### `muclip_sync_set_file_save_dir`
```c
int32_t muclip_sync_set_file_save_dir(MuClipSyncHandle* handle, const char* save_dir);
```
- **功能**：设置接收到文件的默认存放目录（例如 Windows 下的 `C:\Users\<Name>\Downloads\MuClip`）。

#### `muclip_sync_set_file_callbacks`
```c
void muclip_sync_set_file_callbacks(
    MuClipSyncHandle* handle,
    MuClipFileProgressCallback progress_cb,
    MuClipFileCompletedCallback completed_cb,
    MuClipFileOfferCallback offer_cb,
    void* user_data
);
```
- **功能**：统一注册文件传输的所有生命周期回调。

#### `muclip_sync_send_file`
```c
char* muclip_sync_send_file(
    MuClipSyncHandle* handle,
    const char* peer_addr,   // 对端 IP:Port
    const char* file_path    // 本地需要发送的文件绝对路径
);
```
- **功能**：异步启动文件传输线程。
- **返回**：本次传输的唯一任务 ID（`transfer_id`，如 `"1727600000000_123456"`），需调用 `muclip_core_free_string` 释放。失败返回 `NULL`。

#### `muclip_sync_cancel_file_transfer`
```c
int32_t muclip_sync_cancel_file_transfer(MuClipSyncHandle* handle, const char* transfer_id);
```
- **功能**：随时取消正在进行的发送或接收传输任务。成功返回 `0`，失败返回 `-1`。

---

## 4. C# (.NET / Windows) 接入核心规范与避坑指南

跨语言交互 (P/Invoke) 最容易引发内存泄漏、崩溃（Access Violation 0xC0000005）与多线程死锁。接入 Windows 时请务必遵循以下三大黄金法则：

### 4.1 黄金法则一：Native 字符串内存管理与释放

> [!CAUTION]
> **绝对不能**直接在 P/Invoke 签名中使用 `[return: MarshalAs(UnmanagedType.LPStr)] string`！
> 
> 原因：.NET CLR 在收到 `string` 返回值后，会默认调用 Windows 的 `CoTaskMemFree` 试图释放该指针。然而 Rust 的字符串是由 Rust 的全局内存分配器（Jemalloc/System Mimalloc）在 Rust 堆上分配的，混合分配器调用会导致**堆损坏（Heap Corruption）并引发程序硬崩溃退出**。

**正确做法**：
1. P/Invoke 签名中返回值声明为 `IntPtr`。
2. 使用 `Marshal.PtrToStringUTF8(ptr)` 拷贝出托管 `string`。
3. 随后立即调用 `muclip_core_free_string(ptr)`。

```csharp
// 正确范例封装辅助函数：
public static string? PtrToStringAndFree(IntPtr ptr)
{
    if (ptr == IntPtr.Zero) return null;
    try
    {
        return Marshal.PtrToStringUTF8(ptr);
    }
    finally
    {
        NativeMethods.muclip_core_free_string(ptr);
    }
}
```

### 4.2 黄金法则二：回调委托防 GC 回收 (Delegate GC Pinning)

> [!WARNING]
> 当你将一个 C# 委托传递给原生代码（例如 `muclip_sync_set_callback`）时，原生层只保存了一个函数指针。如果你的 C# 代码仅在方法内部临时创建该委托，一旦方法退出，**.NET 垃圾回收器 (GC) 会在几毫秒后将该委托回收**。当下一次底层收到剪贴板推送试图调用该指针时，将直接抛出 `System.ExecutionEngineException` 或 Access Violation 闪退。

**正确做法**：
- 回调委托必须作为所在服务类的**私有常驻字段**强引用持有，或者使用 `GCHandle.Alloc(delegate, GCHandleType.Normal)` 进行锁定，确保生命周期贯穿引擎运行始终。
- 声明特性：`[UnmanagedFunctionPointer(CallingConvention.Cdecl)]`。

### 4.3 黄金法则三：结构体固定缓冲区编组

`MuClipPairResult` 结构体包含固定大小字节数组：
- 使用 `[StructLayout(LayoutKind.Sequential)]`。
- 固定数组字段标注 `[MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]`。
- 解析字符串时读取至首个 `\0` 为止。

---

## 5. C# 开箱即用完整封装代码库 (Ready-to-use Wrapper)

你可以直接将以下 3 个代码文件放入你的 Windows C# 项目（如 `MuClip.Windows/Core/`，在 `.csproj` 中开启 `<AllowUnsafeBlocks>true</AllowUnsafeBlocks>`）中无缝使用。所有批量数据查询均采用 **`muclip_*_pooled` + `ReadOnlySpan<byte>` 二进制零拷贝解析**，彻底消除了 JSON 序列化/反序列化开销。

### 5.1 NativeMethods.cs (全量 P/Invoke 声明)

```csharp
using System;
using System.Runtime.InteropServices;

namespace MuClip.Core.Native
{
    [StructLayout(LayoutKind.Sequential)]
    public struct MuClipPairResult
    {
        public int Success; // 0=成功, 1=拒绝, 2=PIN错误, 3=超时, -1=错误
        
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
        public byte[] ResponderDeviceId;
        
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
        public byte[] ResponderDeviceName;
        
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] ErrorMessage;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 65)]
        public byte[] LongTermKey;

        public string GetDeviceId() => System.Text.Encoding.UTF8.GetString(ResponderDeviceId).TrimEnd('\0');
        public string GetDeviceName() => System.Text.Encoding.UTF8.GetString(ResponderDeviceName).TrimEnd('\0');
        public string GetErrorMessage() => System.Text.Encoding.UTF8.GetString(ErrorMessage).TrimEnd('\0');
        public string GetLongTermKey() => System.Text.Encoding.UTF8.GetString(LongTermKey).TrimEnd('\0');
    }

    // 委托声明
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void MuClipClipboardCallback(
        IntPtr content, IntPtr contentType, IntPtr deviceId, IntPtr deviceName, IntPtr userData);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void MuClipPairRequestCallback(
        IntPtr requestId, IntPtr deviceId, IntPtr deviceName, IntPtr peerIp, IntPtr userData);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void MuClipPairSuccessCallback(
        IntPtr deviceId, IntPtr deviceName, IntPtr peerIp, IntPtr pin, IntPtr userData);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void MuClipFileProgressCallback(
        IntPtr transferId, ulong transferredBytes, ulong totalBytes, ulong speedBps, int isSend, IntPtr userData);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void MuClipFileCompletedCallback(
        IntPtr transferId, IntPtr filePath, int isSend, int success, IntPtr errorMsg, IntPtr userData);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void MuClipFileOfferCallback(
        IntPtr transferId, IntPtr fromDeviceId, IntPtr fromDeviceName, IntPtr fileName, ulong fileSize, IntPtr userData);

    public static class NativeMethods
    {
        private const string DllName = "muclip_core.dll";

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void muclip_core_free_string(IntPtr s);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr muclip_core_version();

        // 原生零拷贝内存池 (Zero-Copy Binary Pool)
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong muclip_pool_acquire(nuint minCapacity, out IntPtr outPtr, out nuint outCap);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int muclip_pool_release(ulong leaseId);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void muclip_pool_clear();

        // 存储与 CRUD (二进制内存池接口)
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr muclip_core_new([MarshalAs(UnmanagedType.LPUTF8Str)] string dbPath);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr muclip_core_new_in_memory();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void muclip_core_free(IntPtr handle);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern long muclip_core_add_history(IntPtr handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string content);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern long muclip_core_add_history_buffer(IntPtr handle, IntPtr dataPtr, nuint dataLen);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong muclip_core_query_history_pooled(IntPtr handle, nuint limit, out IntPtr outPtr, out nuint outLen);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong muclip_core_search_history_pooled(IntPtr handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string query, nuint limit, out IntPtr outPtr, out nuint outLen);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong muclip_core_get_cached_items_pooled(IntPtr handle, out IntPtr outPtr, out nuint outLen);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int muclip_core_delete_history(IntPtr handle, long id);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int muclip_core_clear_history(IntPtr handle);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int muclip_core_cleanup_history(IntPtr handle, uint days);

        // 常用语 (二进制内存池接口)
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern long muclip_core_add_phrase(IntPtr handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string content);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int muclip_core_edit_phrase(IntPtr handle, long id, [MarshalAs(UnmanagedType.LPUTF8Str)] string newContent);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int muclip_core_delete_phrase(IntPtr handle, long id);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int muclip_core_update_phrase_used(IntPtr handle, long id);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong muclip_core_query_phrases_pooled(IntPtr handle, out IntPtr outPtr, out nuint outLen);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong muclip_core_search_phrases_pooled(IntPtr handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string query, out IntPtr outPtr, out nuint outLen);

        // 分析与预览 (二进制内存池接口)
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr muclip_core_format_preview([MarshalAs(UnmanagedType.LPUTF8Str)] string text, nuint maxChars);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong muclip_core_analyze_content_pooled([MarshalAs(UnmanagedType.LPUTF8Str)] string text, out IntPtr outPtr, out nuint outLen);

        // 同步引擎
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr muclip_sync_start(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string deviceId,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string deviceName,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string deviceType,
            ushort syncPort,
            ushort discoveryPort,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string pairingPin
        );

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void muclip_sync_stop(IntPtr handle);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ushort muclip_sync_get_bound_port(IntPtr handle);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong muclip_sync_get_active_peers_pooled(IntPtr handle, out IntPtr outPtr, out nuint outLen);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong muclip_sync_get_all_peers_pooled(IntPtr handle, out IntPtr outPtr, out nuint outLen);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int muclip_sync_add_manual_peer(IntPtr handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string addr);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int muclip_sync_remove_manual_peer(IntPtr handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string addr);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong muclip_sync_get_manual_peers_pooled(IntPtr handle, out IntPtr outPtr, out nuint outLen);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int muclip_sync_set_pairing_pin(IntPtr handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string pin);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern nuint muclip_sync_broadcast(
            IntPtr handle,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string text,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string contentType
        );

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void muclip_sync_set_callback(IntPtr handle, MuClipClipboardCallback? callback, IntPtr userData);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void muclip_sync_set_pair_request_callback(IntPtr handle, MuClipPairRequestCallback? callback, IntPtr userData);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void muclip_sync_set_pair_success_callback(IntPtr handle, MuClipPairSuccessCallback? callback, IntPtr userData);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int muclip_sync_respond_pair(
            IntPtr handle,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string requestId,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string pin,
            int accept
        );

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int muclip_sync_request_pair(
            IntPtr handle,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string peerAddr,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string pin,
            uint timeoutSecs,
            out MuClipPairResult outResult
        );

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int muclip_sync_add_paired_device(IntPtr handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string deviceId);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int muclip_sync_remove_paired_device(IntPtr handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string deviceId);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int muclip_sync_trigger_scan(IntPtr handle);

        // 文件传输
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr muclip_sync_send_file(
            IntPtr handle,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string peerAddr,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string filePath
        );

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int muclip_sync_cancel_file_transfer(IntPtr handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string transferId);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int muclip_sync_set_file_save_dir(IntPtr handle, [MarshalAs(UnmanagedType.LPUTF8Str)] string saveDir);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void muclip_sync_set_file_callbacks(
            IntPtr handle,
            MuClipFileProgressCallback? progressCb,
            MuClipFileCompletedCallback? completedCb,
            MuClipFileOfferCallback? offerCb,
            IntPtr userData
        );
    }
}
```

---

### 5.2 DataModels.cs (强类型 DTO 实体)

```csharp
namespace MuClip.Core.Models
{
    public class HistoryItem
    {
        public long Id { get; set; }
        public string Content { get; set; } = string.Empty;
        public string CreatedAt { get; set; } = string.Empty;
        public string LastUsedAt { get; set; } = string.Empty;
        public string ContentType { get; set; } = "plain_text";
        public ulong CharCount { get; set; }
        public ulong LineCount { get; set; }
        public ulong ByteCount { get; set; }
        public string Preview { get; set; } = string.Empty;
    }

    public class PhraseItem
    {
        public long Id { get; set; }
        public string Content { get; set; } = string.Empty;
        public string CreatedAt { get; set; } = string.Empty;
        public string LastUsedAt { get; set; } = string.Empty;
        public long SortOrder { get; set; }
        public string ContentType { get; set; } = "plain_text";
        public ulong CharCount { get; set; }
        public ulong LineCount { get; set; }
        public ulong ByteCount { get; set; }
        public string Preview { get; set; } = string.Empty;
    }

    public class PeerInfo
    {
        public string DeviceId { get; set; } = string.Empty;
        public string DeviceName { get; set; } = string.Empty;
        public string DeviceType { get; set; } = string.Empty;
        public string Ip { get; set; } = string.Empty;
        public ushort SyncPort { get; set; }
        public ulong LastSeenMs { get; set; }
        public bool IsOnline { get; set; }
        public string Fingerprint { get; set; } = string.Empty;
        public bool IsPaired { get; set; }
        public bool IsManual { get; set; }
        public string Endpoint => $"{Ip}:{SyncPort}";
    }

    public class ContentAnalysis
    {
        public string ContentType { get; set; } = "plain_text";
        public ulong CharCount { get; set; }
        public ulong LineCount { get; set; }
        public ulong ByteCount { get; set; }
        public string Preview { get; set; } = string.Empty;
    }

    public class FileProgressEvent
    {
        public string TransferId { get; set; } = string.Empty;
        public ulong TransferredBytes { get; set; }
        public ulong TotalBytes { get; set; }
        public ulong SpeedBps { get; set; }
        public bool IsSend { get; set; }
        public double ProgressPercent => TotalBytes > 0 ? (double)TransferredBytes / TotalBytes * 100.0 : 0.0;
        public double SpeedMBs => (double)SpeedBps / (1024.0 * 1024.0);
    }

    public class FileCompletedEvent
    {
        public string TransferId { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public bool IsSend { get; set; }
        public bool Success { get; set; }
        public string ErrorMessage { get; set; } = string.Empty;
    }
}
```

---

### 5.3 MuClipCoreService.cs (高层单例服务与零拷贝二进制解码)

```csharp
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using MuClip.Core.Models;
using MuClip.Core.Native;

namespace MuClip.Core
{
    /// <summary>
    /// 栈上分配的零拷贝 Little-Endian 二进制游标读取器，直接基于 Rust 内存池裸指针包装的 ReadOnlySpan&lt;byte&gt; 读取。
    /// </summary>
    internal ref struct BinarySpanReader
    {
        private readonly ReadOnlySpan<byte> _span;
        private int _pos;

        public BinarySpanReader(ReadOnlySpan<byte> span)
        {
            _span = span;
            _pos = 0;
        }

        public bool ReadBool() => _span[_pos++] != 0;

        public int ReadInt32()
        {
            int val = BinaryPrimitives.ReadInt32LittleEndian(_span.Slice(_pos, 4));
            _pos += 4;
            return val;
        }

        public uint ReadUInt32()
        {
            uint val = BinaryPrimitives.ReadUInt32LittleEndian(_span.Slice(_pos, 4));
            _pos += 4;
            return val;
        }

        public long ReadInt64()
        {
            long val = BinaryPrimitives.ReadInt64LittleEndian(_span.Slice(_pos, 8));
            _pos += 8;
            return val;
        }

        public string ReadString()
        {
            int len = ReadInt32();
            if (len <= 0) return string.Empty;
            string s = Encoding.UTF8.GetString(_span.Slice(_pos, len));
            _pos += len;
            return s;
        }
    }

    public class MuClipCoreService : IDisposable
    {
        private static readonly Lazy<MuClipCoreService> _instance = new(() => new MuClipCoreService());
        public static MuClipCoreService Instance => _instance.Value;

        private IntPtr _coreHandle = IntPtr.Zero;
        private IntPtr _syncHandle = IntPtr.Zero;

        // 强引用持有回调委托，防止被 .NET GC 垃圾回收导致崩溃
        private readonly MuClipClipboardCallback _clipboardCb;
        private readonly MuClipPairRequestCallback _pairRequestCb;
        private readonly MuClipPairSuccessCallback _pairSuccessCb;
        private readonly MuClipFileProgressCallback _fileProgressCb;
        private readonly MuClipFileCompletedCallback _fileCompletedCb;
        private readonly MuClipFileOfferCallback _fileOfferCb;

        // 供 UI 层订阅的强类型事件
        public event Action<string, string, string, string>? OnClipboardReceived;
        public event Action<string, string, string, string>? OnPairRequested; // reqId, devId, devName, ip
        public event Action<string, string, string, string>? OnPairSucceeded; // devId, devName, ip, pin
        public event Action<FileProgressEvent>? OnFileProgress;
        public event Action<FileCompletedEvent>? OnFileCompleted;
        public event Action<string, string, string, string, ulong>? OnFileOffer; // tid, fromId, fromName, fileName, size

        private MuClipCoreService()
        {
            _clipboardCb = HandleClipboardReceived;
            _pairRequestCb = HandlePairRequested;
            _pairSuccessCb = HandlePairSucceeded;
            _fileProgressCb = HandleFileProgress;
            _fileCompletedCb = HandleFileCompleted;
            _fileOfferCb = HandleFileOffer;
        }

        public void Initialize(string dbPath, string deviceId, string deviceName, string pin = "")
        {
            if (_coreHandle != IntPtr.Zero) return;

            string dir = Path.GetDirectoryName(dbPath) ?? "";
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            _coreHandle = NativeMethods.muclip_core_new(dbPath);
            if (_coreHandle == IntPtr.Zero)
            {
                throw new InvalidOperationException($"无法初始化 MuClip SQLite 数据库: {dbPath}");
            }

            _syncHandle = NativeMethods.muclip_sync_start(
                deviceId,
                deviceName,
                "Windows",
                0, // 默认 42424
                0, // 默认 42110
                pin
            );

            if (_syncHandle != IntPtr.Zero)
            {
                // 注册剪贴板回调
                NativeMethods.muclip_sync_set_callback(_syncHandle, _clipboardCb, IntPtr.Zero);
                NativeMethods.muclip_sync_set_pair_request_callback(_syncHandle, _pairRequestCb, IntPtr.Zero);
                NativeMethods.muclip_sync_set_pair_success_callback(_syncHandle, _pairSuccessCb, IntPtr.Zero);

                // 注册文件传输回调
                NativeMethods.muclip_sync_set_file_callbacks(
                    _syncHandle,
                    _fileProgressCb,
                    _fileCompletedCb,
                    _fileOfferCb,
                    IntPtr.Zero
                );
            }
        }

        // ==================== 字符串与二进制池内存释放辅助 ====================
        private static string PtrToStringAndFree(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero) return string.Empty;
            try
            {
                return Marshal.PtrToStringUTF8(ptr) ?? string.Empty;
            }
            finally
            {
                NativeMethods.muclip_core_free_string(ptr);
            }
        }

        private static unsafe List<HistoryItem> ReadHistoryFromPooled(ulong leaseId, IntPtr ptr, nuint len)
        {
            if (leaseId == 0 || ptr == IntPtr.Zero || len == 0) return new();
            try
            {
                var reader = new BinarySpanReader(new ReadOnlySpan<byte>((void*)ptr, (int)len));
                uint count = reader.ReadUInt32();
                var list = new List<HistoryItem>((int)count);
                for (uint i = 0; i < count; i++)
                {
                    long id = reader.ReadInt64();
                    ulong charCount = (ulong)reader.ReadInt32();
                    ulong lineCount = (ulong)reader.ReadInt32();
                    ulong byteCount = (ulong)reader.ReadInt32();
                    string content = reader.ReadString();
                    string contentType = reader.ReadString();
                    string preview = reader.ReadString();
                    string createdAt = reader.ReadString();
                    string lastUsedAt = reader.ReadString();
                    list.Add(new HistoryItem
                    {
                        Id = id,
                        Content = content,
                        ContentType = string.IsNullOrEmpty(contentType) ? "plain_text" : contentType,
                        CharCount = charCount,
                        LineCount = lineCount,
                        ByteCount = byteCount,
                        Preview = preview,
                        CreatedAt = createdAt,
                        LastUsedAt = lastUsedAt
                    });
                }
                return list;
            }
            finally
            {
                NativeMethods.muclip_pool_release(leaseId);
            }
        }

        private static unsafe List<PhraseItem> ReadPhrasesFromPooled(ulong leaseId, IntPtr ptr, nuint len)
        {
            if (leaseId == 0 || ptr == IntPtr.Zero || len == 0) return new();
            try
            {
                var reader = new BinarySpanReader(new ReadOnlySpan<byte>((void*)ptr, (int)len));
                uint count = reader.ReadUInt32();
                var list = new List<PhraseItem>((int)count);
                for (uint i = 0; i < count; i++)
                {
                    long id = reader.ReadInt64();
                    long sortOrder = reader.ReadInt64();
                    ulong charCount = (ulong)reader.ReadInt32();
                    ulong lineCount = (ulong)reader.ReadInt32();
                    ulong byteCount = (ulong)reader.ReadInt32();
                    string content = reader.ReadString();
                    string contentType = reader.ReadString();
                    string preview = reader.ReadString();
                    string createdAt = reader.ReadString();
                    string lastUsedAt = reader.ReadString();
                    list.Add(new PhraseItem
                    {
                        Id = id,
                        SortOrder = sortOrder,
                        Content = content,
                        ContentType = string.IsNullOrEmpty(contentType) ? "plain_text" : contentType,
                        CharCount = charCount,
                        LineCount = lineCount,
                        ByteCount = byteCount,
                        Preview = preview,
                        CreatedAt = createdAt,
                        LastUsedAt = lastUsedAt
                    });
                }
                return list;
            }
            finally
            {
                NativeMethods.muclip_pool_release(leaseId);
            }
        }

        private static unsafe List<PeerInfo> ReadPeersFromPooled(ulong leaseId, IntPtr ptr, nuint len)
        {
            if (leaseId == 0 || ptr == IntPtr.Zero || len == 0) return new();
            try
            {
                var reader = new BinarySpanReader(new ReadOnlySpan<byte>((void*)ptr, (int)len));
                uint count = reader.ReadUInt32();
                var list = new List<PeerInfo>((int)count);
                for (uint i = 0; i < count; i++)
                {
                    ushort syncPort = (ushort)reader.ReadInt32();
                    ulong lastSeenMs = (ulong)reader.ReadInt64();
                    bool isOnline = reader.ReadBool();
                    bool isPaired = reader.ReadBool();
                    bool isManual = reader.ReadBool();
                    string deviceId = reader.ReadString();
                    string deviceName = reader.ReadString();
                    string deviceType = reader.ReadString();
                    string ip = reader.ReadString();
                    string fingerprint = reader.ReadString();
                    list.Add(new PeerInfo
                    {
                        DeviceId = deviceId,
                        DeviceName = deviceName,
                        DeviceType = deviceType,
                        Ip = ip,
                        SyncPort = syncPort,
                        LastSeenMs = lastSeenMs,
                        IsOnline = isOnline,
                        Fingerprint = fingerprint,
                        IsPaired = isPaired,
                        IsManual = isManual
                    });
                }
                return list;
            }
            finally
            {
                NativeMethods.muclip_pool_release(leaseId);
            }
        }

        // ==================== 剪贴板与常用语 CRUD (零拷贝二进制) ====================
        public long AddHistory(string text)
        {
            if (_coreHandle == IntPtr.Zero) return -1;
            return NativeMethods.muclip_core_add_history(_coreHandle, text);
        }

        public List<HistoryItem> QueryHistory(int limit = 50)
        {
            if (_coreHandle == IntPtr.Zero) return new();
            ulong leaseId = NativeMethods.muclip_core_query_history_pooled(_coreHandle, (nuint)limit, out IntPtr ptr, out nuint len);
            return ReadHistoryFromPooled(leaseId, ptr, len);
        }

        public List<HistoryItem> SearchHistory(string query, int limit = 50)
        {
            if (_coreHandle == IntPtr.Zero) return new();
            ulong leaseId = NativeMethods.muclip_core_search_history_pooled(_coreHandle, query, (nuint)limit, out IntPtr ptr, out nuint len);
            return ReadHistoryFromPooled(leaseId, ptr, len);
        }

        public List<HistoryItem> GetCachedItems()
        {
            if (_coreHandle == IntPtr.Zero) return new();
            ulong leaseId = NativeMethods.muclip_core_get_cached_items_pooled(_coreHandle, out IntPtr ptr, out nuint len);
            return ReadHistoryFromPooled(leaseId, ptr, len);
        }

        public List<PhraseItem> QueryPhrases()
        {
            if (_coreHandle == IntPtr.Zero) return new();
            ulong leaseId = NativeMethods.muclip_core_query_phrases_pooled(_coreHandle, out IntPtr ptr, out nuint len);
            return ReadPhrasesFromPooled(leaseId, ptr, len);
        }

        public List<PhraseItem> SearchPhrases(string query)
        {
            if (_coreHandle == IntPtr.Zero) return new();
            ulong leaseId = NativeMethods.muclip_core_search_phrases_pooled(_coreHandle, query, out IntPtr ptr, out nuint len);
            return ReadPhrasesFromPooled(leaseId, ptr, len);
        }

        public unsafe ContentAnalysis AnalyzeContent(string text)
        {
            ulong leaseId = NativeMethods.muclip_core_analyze_content_pooled(text, out IntPtr ptr, out nuint len);
            if (leaseId == 0 || ptr == IntPtr.Zero || len == 0)
            {
                return new ContentAnalysis { ContentType = "plain_text", CharCount = (ulong)text.Length, LineCount = 1, Preview = text };
            }
            try
            {
                var reader = new BinarySpanReader(new ReadOnlySpan<byte>((void*)ptr, (int)len));
                ulong charCount = (ulong)reader.ReadInt32();
                ulong lineCount = (ulong)reader.ReadInt32();
                ulong byteCount = (ulong)reader.ReadInt32();
                string contentType = reader.ReadString();
                string preview = reader.ReadString();
                return new ContentAnalysis
                {
                    ContentType = string.IsNullOrEmpty(contentType) ? "plain_text" : contentType,
                    CharCount = charCount,
                    LineCount = lineCount,
                    ByteCount = byteCount,
                    Preview = preview
                };
            }
            finally
            {
                NativeMethods.muclip_pool_release(leaseId);
            }
        }

        public bool DeleteHistory(long id)
        {
            return _coreHandle != IntPtr.Zero && NativeMethods.muclip_core_delete_history(_coreHandle, id) == 0;
        }

        public void ClearHistory()
        {
            if (_coreHandle != IntPtr.Zero) NativeMethods.muclip_core_clear_history(_coreHandle);
        }

        // ==================== 同步与广播 (零拷贝二进制) ====================
        public void BroadcastClipboard(string text, string contentType = "text")
        {
            if (_syncHandle != IntPtr.Zero)
            {
                NativeMethods.muclip_sync_broadcast(_syncHandle, text, contentType);
            }
        }

        public List<PeerInfo> GetActivePeers()
        {
            if (_syncHandle == IntPtr.Zero) return new();
            ulong leaseId = NativeMethods.muclip_sync_get_active_peers_pooled(_syncHandle, out IntPtr ptr, out nuint len);
            return ReadPeersFromPooled(leaseId, ptr, len);
        }

        public List<PeerInfo> GetAllPeers()
        {
            if (_syncHandle == IntPtr.Zero) return new();
            ulong leaseId = NativeMethods.muclip_sync_get_all_peers_pooled(_syncHandle, out IntPtr ptr, out nuint len);
            return ReadPeersFromPooled(leaseId, ptr, len);
        }

        public unsafe List<string> GetManualPeers()
        {
            if (_syncHandle == IntPtr.Zero) return new();
            ulong leaseId = NativeMethods.muclip_sync_get_manual_peers_pooled(_syncHandle, out IntPtr ptr, out nuint len);
            if (leaseId == 0 || ptr == IntPtr.Zero || len == 0) return new();
            try
            {
                var reader = new BinarySpanReader(new ReadOnlySpan<byte>((void*)ptr, (int)len));
                uint count = reader.ReadUInt32();
                var list = new List<string>((int)count);
                for (uint i = 0; i < count; i++)
                {
                    list.Add(reader.ReadString());
                }
                return list;
            }
            finally
            {
                NativeMethods.muclip_pool_release(leaseId);
            }
        }

        public void AddManualPeer(string endpoint)
        {
            if (_syncHandle != IntPtr.Zero) NativeMethods.muclip_sync_add_manual_peer(_syncHandle, endpoint);
        }

        public void RemoveManualPeer(string endpoint)
        {
            if (_syncHandle != IntPtr.Zero) NativeMethods.muclip_sync_remove_manual_peer(_syncHandle, endpoint);
        }

        public bool RequestPair(string peerEndpoint, string pin, out string errorMessage)
        {
            errorMessage = string.Empty;
            if (_syncHandle == IntPtr.Zero)
            {
                errorMessage = "同步引擎未启动";
                return false;
            }

            int code = NativeMethods.muclip_sync_request_pair(
                _syncHandle,
                peerEndpoint,
                pin,
                30,
                out MuClipPairResult res
            );

            if (code == 0) return true;
            errorMessage = res.GetErrorMessage();
            if (string.IsNullOrEmpty(errorMessage))
            {
                errorMessage = code switch
                {
                    1 => "对方拒绝了配对请求",
                    2 => "配对 PIN 码错误",
                    3 => "配对等待超时",
                    _ => $"配对失败 (代码: {code})"
                };
            }
            return false;
        }

        public void RespondPair(string requestId, string pin, bool accept)
        {
            if (_syncHandle != IntPtr.Zero)
            {
                NativeMethods.muclip_sync_respond_pair(_syncHandle, requestId, pin, accept ? 1 : 0);
            }
        }

        public void UnpairDevice(string deviceId)
        {
            if (_syncHandle != IntPtr.Zero)
            {
                NativeMethods.muclip_sync_remove_paired_device(_syncHandle, deviceId);
            }
        }

        public void TriggerDiscoveryScan()
        {
            if (_syncHandle != IntPtr.Zero)
            {
                NativeMethods.muclip_sync_trigger_scan(_syncHandle);
            }
        }

        // ==================== 文件传输 ====================
        public string? SendFile(string peerEndpoint, string filePath)
        {
            if (_syncHandle == IntPtr.Zero || !File.Exists(filePath)) return null;
            IntPtr ptr = NativeMethods.muclip_sync_send_file(_syncHandle, peerEndpoint, filePath);
            return PtrToStringAndFree(ptr);
        }

        public bool CancelFileTransfer(string transferId)
        {
            return _syncHandle != IntPtr.Zero && NativeMethods.muclip_sync_cancel_file_transfer(_syncHandle, transferId) == 0;
        }

        public void SetFileSaveDirectory(string dir)
        {
            if (_syncHandle != IntPtr.Zero)
            {
                if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
                NativeMethods.muclip_sync_set_file_save_dir(_syncHandle, dir);
            }
        }

        // ==================== 原生回调桥接分发 ====================
        private void HandleClipboardReceived(IntPtr content, IntPtr contentType, IntPtr deviceId, IntPtr deviceName, IntPtr userData)
        {
            string c = Marshal.PtrToStringUTF8(content) ?? "";
            string ct = Marshal.PtrToStringUTF8(contentType) ?? "text";
            string did = Marshal.PtrToStringUTF8(deviceId) ?? "";
            string dname = Marshal.PtrToStringUTF8(deviceName) ?? "";

            // 自动存入本地 SQLite
            AddHistory(c);

            // 触发上层 UI 事件
            OnClipboardReceived?.Invoke(c, ct, did, dname);
        }

        private void HandlePairRequested(IntPtr reqId, IntPtr devId, IntPtr devName, IntPtr ip, IntPtr userData)
        {
            OnPairRequested?.Invoke(
                Marshal.PtrToStringUTF8(reqId) ?? "",
                Marshal.PtrToStringUTF8(devId) ?? "",
                Marshal.PtrToStringUTF8(devName) ?? "",
                Marshal.PtrToStringUTF8(ip) ?? ""
            );
        }

        private void HandlePairSucceeded(IntPtr devId, IntPtr devName, IntPtr ip, IntPtr pin, IntPtr userData)
        {
            OnPairSucceeded?.Invoke(
                Marshal.PtrToStringUTF8(devId) ?? "",
                Marshal.PtrToStringUTF8(devName) ?? "",
                Marshal.PtrToStringUTF8(ip) ?? "",
                Marshal.PtrToStringUTF8(pin) ?? ""
            );
        }

        private void HandleFileProgress(IntPtr tid, ulong transferred, ulong total, ulong speed, int isSend, IntPtr userData)
        {
            OnFileProgress?.Invoke(new FileProgressEvent
            {
                TransferId = Marshal.PtrToStringUTF8(tid) ?? "",
                TransferredBytes = transferred,
                TotalBytes = total,
                SpeedBps = speed,
                IsSend = isSend != 0
            });
        }

        private void HandleFileCompleted(IntPtr tid, IntPtr path, int isSend, int success, IntPtr errMsg, IntPtr userData)
        {
            OnFileCompleted?.Invoke(new FileCompletedEvent
            {
                TransferId = Marshal.PtrToStringUTF8(tid) ?? "",
                FilePath = Marshal.PtrToStringUTF8(path) ?? "",
                IsSend = isSend != 0,
                Success = success != 0,
                ErrorMessage = Marshal.PtrToStringUTF8(errMsg) ?? ""
            });
        }

        private void HandleFileOffer(IntPtr tid, IntPtr fromId, IntPtr fromName, IntPtr fileName, ulong size, IntPtr userData)
        {
            OnFileOffer?.Invoke(
                Marshal.PtrToStringUTF8(tid) ?? "",
                Marshal.PtrToStringUTF8(fromId) ?? "",
                Marshal.PtrToStringUTF8(fromName) ?? "",
                Marshal.PtrToStringUTF8(fileName) ?? "",
                size
            );
        }

        public void Dispose()
        {
            if (_syncHandle != IntPtr.Zero)
            {
                NativeMethods.muclip_sync_stop(_syncHandle);
                _syncHandle = IntPtr.Zero;
            }
            if (_coreHandle != IntPtr.Zero)
            {
                NativeMethods.muclip_core_free(_coreHandle);
                _coreHandle = IntPtr.Zero;
            }
        }
    }
}
```

---

## 6. C# 快速接入示例 (Quick Start)

### 场景一：启动服务并监听远端剪贴板
```csharp
// 1. 初始化核心引擎与同步服务
string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
string dbPath = Path.Combine(appData, "MuClip", "muclip.db");

var service = MuClipCoreService.Instance;
service.Initialize(
    dbPath: dbPath,
    deviceId: "win-pc-" + Environment.MachineName,
    deviceName: Environment.MachineName,
    pin: "666888" // 本机 PIN 码
);

// 2. 订阅远端剪贴板推送
service.OnClipboardReceived += (content, type, devId, devName) =>
{
    Console.WriteLine($"[收到来自 {devName} 的剪贴板]: {content}");
    // 写入 Windows 本地剪贴板 (WPF / WinForms 需在 UI 线程执行):
    // Application.Current.Dispatcher.Invoke(() => Clipboard.SetText(content));
};

// 3. 当本地 Windows 剪贴板发生变化时，广播给所有已配对设备：
service.BroadcastClipboard("Hello from Windows C#!");
```

### 场景二：局域网发现与配对
```csharp
// 1. 获取当前所有在线设备
var peers = service.GetActivePeers();
foreach (var peer in peers)
{
    Console.WriteLine($"发现设备: {peer.DeviceName} ({peer.Endpoint}), 已配对: {peer.IsPaired}");
}

// 2. 向某台未配对设备发起配对握手
if (service.RequestPair("192.168.1.105:42424", "123456", out string error))
{
    Console.WriteLine("配对成功！");
}
else
{
    Console.WriteLine($"配对失败: {error}");
}

// 3. 监听其他设备发来的配对请求
service.OnPairRequested += (reqId, devId, devName, ip) =>
{
    // 弹出 Windows 提示窗口让用户确认
    bool userAccepted = true; // 假设用户点击同意
    service.RespondPair(reqId, "123456", userAccepted);
};
```

### 场景三：高速发送文件并显示进度条
```csharp
// 设置下载文件接收目录
service.SetFileSaveDirectory(@"C:\Users\Public\Downloads\MuClip");

// 监听进度与速率
service.OnFileProgress += e =>
{
    Console.WriteLine($"[{e.TransferId}] 进度: {e.ProgressPercent:F1}% | 速度: {e.SpeedMBs:F2} MB/s");
};

service.OnFileCompleted += e =>
{
    if (e.Success)
        Console.WriteLine($"传输完成: {e.FilePath}");
    else
        Console.WriteLine($"传输失败: {e.ErrorMessage}");
};

// 异步发送 1GB 大文件
string? tid = service.SendFile("192.168.1.105:42424", @"D:\Movies\demo.mp4");
Console.WriteLine($"传输任务已启动, Task ID: {tid}");
```

---

## 7. 许可证与贡献
MuClip 遵循 MIT License 协议开源。
欢迎提交 Issue 与 Pull Request 共同完善跨平台生态！
