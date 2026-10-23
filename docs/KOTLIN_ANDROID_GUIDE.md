# MuClip Core Android (Kotlin / JNI) 核心接入与零拷贝开发指南

本文档面向 Android (Kotlin) 客户端开发者，详细说明如何通过 **JNI + `DirectByteBuffer` 堆外内存池 + Little-Endian 二进制线格式** 调用 `muclip-core` (`libmuclip_core.so`) 的全部核心能力。

---

## 目录

1. [架构总览与零拷贝设计原则](#1-架构总览与零拷贝设计原则)
2. [交叉编译与 Android 工程配置](#2-交叉编译与-android-工程配置)
3. [堆外内存池与二进制线格式规范 (Binary Wire Format)](#3-堆外内存池与二进制线格式规范-binary-wire-format)
4. [核心模块调用指南](#4-核心模块调用指南)
   - [4.1 堆外内存池 (`DirectBufferPool` & `LeasedBuffer`)](#41-堆外内存池-directbufferpool--leasedbuffer)
   - [4.2 数据库、字符统计与内容特征分析 (`MuClipCore`)](#42-数据库字符统计与内容特征分析-muclipcore)
   - [4.3 局域网自发现与端口映射同步引擎 (`MuClipSync`)](#43-局域网自发现与端口映射同步引擎-muclipsync)
   - [4.4 单流 TCP 随机 PIN 配对与双向解绑](#44-单流-tcp-随机-pin-配对与双向解绑)
   - [4.5 原地 AEAD 加密流式文件互传 (`StreamingFileTransfer`)](#45-原地-aead-加密流式文件互传-streamingfiletransfer)
5. [JNI 底层接口全量速查 (`MuClipNative.kt`)](#5-jni-底层接口全量速查-muclipnativekt)
6. [生命周期与关键注意事项](#6-生命周期与关键注意事项)

---

## 1. 架构总览与零拷贝设计原则

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Android App (Kotlin)                            │
│  ┌──────────────────┐  ┌────────────────────┐  ┌─────────────────────┐  │
│  │   MuClipCore     │  │    MuClipSync      │  │StreamingFileTransfer│  │
│  │ (历史/常用语/分析) │  │(发现/映射/配对/广播)│  │ (SAF 零缓存流式互传) │  │
│  └────────┬─────────┘  └─────────┬──────────┘  └──────────┬──────────┘  │
│           └──────────────────────┼────────────────────────┘             │
│                                  ▼                                      │
│           ┌─────────────────────────────────────────────┐               │
│           │  DirectBufferPool (Leased DirectByteBuffer) │               │
│           │  Little-Endian Binary Wire Format (No JSON) │               │
│           └──────────────────────┬──────────────────────┘               │
└──────────────────────────────────┼──────────────────────────────────────┘
                                   │ JNI (rawPtr / Critical Array)
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     libmuclip_core.so (Rust Core)                       │
│  - NativeBufferPool (堆外内存租借池，自动复用 64KB 缓冲块)              │
│  - BinaryCursorWriter (Little-Endian 二进制紧凑编码器，零 JSON 开销)    │
│  - SQLite + LRU Memory Cache (自动计算字符数/行数/字节数/类型/时间)     │
│  - Discovery & Port Mapping (mDNS + UDP 42110 + TCP MSG_HEARTBEAT 探测) │
│  - XChaCha20-Poly1305 / ChaCha20-Poly1305 + X25519 单流配对握手         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 三大核心法则

1. **堆外直接内存传递（DirectByteBuffer + Raw Pointer）**：
   - Rust 侧维护全局线程安全的 `NativeBufferPool`，通过 `env.new_direct_byte_buffer(ptr, cap)` 将堆外内存包装为 `java.nio.ByteBuffer` 租借给 Kotlin，同时返回裸指针 `rawPtr: Long` 和租约号 `leaseId: Long`。
   - **谁分配，谁释放**：Kotlin 侧通过 `DirectBufferPool.useLeased { buf -> ... }` 或 `DirectBufferPool.useBinaryQuery(...)` 在 `finally` 块中自动调用 `nativeReleaseBuffer(leaseId)` 归还内存。
2. **全链路二进制线格式（零 JSON 序列化开销）**：
   - 所有跨 JNI 边界的结构体与列表查询（历史记录、常用语、内容分析、在线/映射节点、配对结果）均采用 **Little-Endian 二进制流** 编码，彻底消除 `serde_json` 与 `org.json` 的文本构建、转义与反射开销。
   - **自适应扩容重试协议**：当 64KB 默认租借缓冲区不足以容纳查询结果时，Rust 编码器不会截断或分配临时堆内存，而是直接返回负数 `-required_bytes`（所需精确字节数）；Kotlin `DirectBufferPool.useBinaryQuery` 自动捕获该返回值并按精确容量重新租借大缓冲区完成读取。
3. **固定缓冲区原地流式加解密（In-Place AEAD）**：
   - 大文件传输在循环外仅分配一次 `ByteArray(128 * 1024 + 16)`，通过 JNI `GetPrimitiveArrayCritical` 原地完成 `XChaCha20-Poly1305` 加解密，循环内零内存分配、零 GC 抖动、零磁盘临时文件缓存（发送端直接读取 SAF `InputStream`）。

---

## 2. 交叉编译与 Android 工程配置

### 2.1 编译 `libmuclip_core.so`

确保已安装 Android NDK 与 `cargo-ndk`：

```powershell
# 1. 添加 Android 编译目标
rustup target add aarch64-linux-android x86_64-linux-android

# 2. 在 MuClip (Rust 核心仓库) 根目录下编译 Release 动态库
cargo ndk -t arm64-v8a build --release

# 3. 拷贝产物至 Android 工程的 jniLibs 目录
Copy-Item -Path "target\aarch64-linux-android\release\libmuclip_core.so" `
          -Destination "..\MuClip-Android\app\src\main\jniLibs\arm64-v8a\libmuclip_core.so" -Force
```

### 2.2 `AndroidManifest.xml` 必需权限

局域网 UDP 组播发现、TCP 同步与前台常驻服务需要声明以下权限：

```xml
<!-- 局域网与外部端口映射通信 -->
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
<!-- 接收局域网 mDNS / UDP 多播信标必需 -->
<uses-permission android:name="android.permission.CHANGE_WIFI_MULTICAST_STATE" />

<!-- 后台同步常驻服务 -->
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE_DATA_SYNC" />
<uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
```

---

## 3. 堆外内存池与二进制线格式规范 (Binary Wire Format)

所有 `*ZeroCopy` 查询接口遵循统一的返回值与字节序约定：

- **字节序**：所有整数统一为 **Little-Endian (`ByteOrder.LITTLE_ENDIAN`)**。
- **返回值约定 (`Int`)**：
  - `> 0`：成功写入堆外缓冲区的总字节数。
  - `0` 或 `-1`：无数据或句柄无效。
  - `< -1`：目标缓冲区容量不足，此时 **`-returnValue` 即为所需的精确字节容量**。
- **基础类型编码**：
  - `u8` / `Boolean`：`1 Byte`（`0` = `false`，非 `0` = `true`）
  - `i32`：`4 Bytes` Little-Endian
  - `i64`：`8 Bytes` Little-Endian
  - `String`：`[i32 byteLength][UTF-8 bytes]`（当 `byteLength == 0` 时后跟 0 字节）
  - `NullableString`：`[i32 byteLength]`（当 `byteLength == -1` 时表示 `null`；`>= 0` 时后跟对应长度的 UTF-8 字节）

### 各数据结构二进制帧布局

| 接口 / 数据类型 | 头部 | 单条记录二进制字段顺序 (Little-Endian) |
| :--- | :--- | :--- |
| **`HistoryItem` 列表**<br>`nativeQueryHistoryZeroCopy`<br>`nativeSearchHistoryZeroCopy` | `[i32 count]` | `id: i64` → `charCount: i32` → `lineCount: i32` → `byteCount: i32` → `content: String` → `contentType: String` → `preview: String` → `createdAt: String` → `lastUsedAt: String` |
| **`PhraseItem` 列表**<br>`nativeQueryPhrasesZeroCopy` | `[i32 count]` | `id: i64` → `sortOrder: i64` → `charCount: i32` → `lineCount: i32` → `byteCount: i32` → `content: String` → `contentType: String` → `preview: String` → `createdAt: String` → `lastUsedAt: String` |
| **`ContentAnalysis`**<br>`nativeAnalyzeContentZeroCopy` | 无 (`1` 条) | `charCount: i32` → `lineCount: i32` → `byteCount: i32` → `contentType: String` → `preview: String` |
| **`PeerInfo` 列表**<br>`nativeGetActivePeersZeroCopy`<br>`nativeGetAllPeersZeroCopy` | `[i32 count]` | `syncPort: i32` → `lastSeenMs: i64` → `isOnline: u8` → `isPaired: u8` → `isManual: u8` → `deviceId: String` → `deviceName: String` → `deviceType: String` → `ip: String` → `fingerprint: String` |
| **`String` 列表**<br>`nativeGetManualPeersZeroCopy` | `[i32 count]` | `endpoint: String` |
| **`PairResult`**<br>`nativeRequestPairZeroCopy` | 无 (`1` 条) | `success: u8` → `errorCode: i32` → `responderDeviceId: String` → `responderDeviceName: String` → `errorMessage: NullableString` → `longTermKey: NullableString` |

---

## 4. 核心模块调用指南

### 4.1 堆外内存池 (`DirectBufferPool` & `LeasedBuffer`)

Kotlin 侧通过 `DirectBufferPool` 管理堆外内存租借，提供两个核心高阶函数：

- **`DirectBufferPool.useLeased(minCapacity) { buf -> ... }`**：租借一块堆外 `LeasedBuffer`，用于向 Rust 写入零拷贝 UTF-8 字符串（`buf.writeUtf8(text)`）并传入 `buf.rawPtr`。
- **`DirectBufferPool.useBinaryQuery(initialCapacity, defaultResult, nativeWriter, decoder)`**：执行二进制查询，自动处理 `< -1` 扩容重试并定位游标。

```kotlin
// 示例：向 Rust 零拷贝写入文本
val rowId: Long = DirectBufferPool.useLeased { buffer ->
    val byteLen = buffer.writeUtf8(clipboardText)
    MuClipNative.nativeAddHistoryZeroCopy(coreHandle, buffer.rawPtr, byteLen)
}
```

---

### 4.2 数据库、字符统计与内容特征分析 (`MuClipCore`)

> **重要说明**：剪贴板数据的 **字符数 (`charCount`)、行数 (`lineCount`)、UTF-8 字节数 (`byteCount`)、内容类型 (`contentType`)、单行摘要 (`preview`) 以及创建/最后使用时间 (`createdAt` / `lastUsedAt`)** 全部由 Rust 核心在入库时自动统计并持久化，Kotlin 端调用 `queryHistory` / `searchHistory` / `queryPhrases` 时直接从二进制流读取即可，无需在客户端重复遍历字符串。

#### 1) 初始化与关闭

```kotlin
// 在 Application.onCreate() 中初始化持久化数据库
val dbFile = File(filesDir, "muclip.db")
val core = MuClipCore.open(dbFile.absolutePath)

// 或在单元测试中初始化内存数据库
val memCore = MuClipCore.openInMemory()

// 退出时释放句柄（会将热缓存自动刷回 SQLite）
core.close()
```

#### 2) 剪贴板历史 CRUD 与全文检索

```kotlin
// 1. 新增或更新剪贴板历史（相同内容自动去重并更新 lastUsedAt 置顶）
val id: Long = core.addHistory("https://github.com/muclip/muclip-core")

// 2. 查询最近 N 条历史记录（优先命中 Rust LRU 内存热缓存，二进制零拷贝返回）
val items: List<HistoryItem> = core.queryHistory(limit = 100)
items.forEach { item ->
    println("ID=${item.id}, 类型=${item.contentType}, 字符=${item.charCount}, 行数=${item.lineCount}, 字节=${item.byteCount}, 时间=${item.createdAt}")
}

// 3. 关键字搜索历史记录
val matched: List<HistoryItem> = core.searchHistory(query = "github", limit = 50)

// 4. 删除单条、清空全部、按天数清理过期记录
core.deleteHistory(id)
val deletedCount: Int = core.cleanupHistory(days = 30)
core.clearHistory()
```

#### 3) 常用语 (Phrases) 与实时内容分析

```kotlin
// 添加与查询常用语（同样自带 charCount / lineCount / byteCount / contentType / preview）
val phraseId: Long = core.addPhrase("常用回复模板内容")
val phrases: List<PhraseItem> = core.queryPhrases()

// 不入库直接分析任意文本特征（识别 url / email / code / json / path / hex_color / phone / number / plain_text）
val analysis: ContentAnalysis = core.analyzeContent("SELECT * FROM history WHERE id = 1;")
// analysis.contentType == "code", analysis.charCount, analysis.lineCount, analysis.byteCount, analysis.preview

// 生成折叠空白符后的单行预览
val preview: String = core.formatPreview("第一行\n   第二行\t第三行", maxChars = 80)
```

#### 4) 安全配置表 (`secure_config`)

```kotlin
// 结合 AndroidKeyStore 加密后存入 Rust SQLite secure_config 表
core.setConfig("long_term_key", encryptedKeyBase64)
val stored: String? = core.getConfig("long_term_key")
```

---

### 4.3 局域网自发现与端口映射同步引擎 (`MuClipSync`)

#### 1) 启动同步引擎与注册回调

在 Android 上启动 `MuClipSync` 前，建议持有 `WifiManager.MulticastLock` 以确保系统不丢弃局域网 mDNS / UDP 多播包：

```kotlin
// 1. 获取 Wi-Fi 组播锁
val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
val multicastLock = wifi?.createMulticastLock("MuClipMDNSLock")?.apply {
    setReferenceCounted(true)
    acquire()
}

// 2. 启动 P2P 同步引擎
val sync = MuClipSync.start(
    deviceId = preferences.deviceId,       // 本机唯一 ID，如 "muclip-android-a1b2c3d4"
    deviceName = preferences.deviceName,   // 本机显示名称，如 Build.MODEL
    deviceType = "Android",
    syncPort = 42424,                      // TCP 监听端口（传 0 默认绑定 42424）
    pairingPin = preferences.pairingPin    // 64位 Hex 协商长期密钥或初始 PIN
)

// 3. 加载已保存的端口映射节点与已配对设备白名单
preferences.getCustomPeers().forEach { endpoint ->
    sync.addManualPeer(endpoint)
}
preferences.getPairedDevices().forEach { devId ->
    sync.addPairedDevice(devId)
}
```

#### 2) 外部端口映射节点管理（FRP / DDNS / Tailscale / 公网映射）

`MuClipSync` 对外部映射节点提供开箱即用的全生命周期支持：

- **支持格式**：`"192.168.1.100:42424"`、纯 IP `"192.168.1.100"`（缺省端口 `42424`）、IPv6 `"[fe80::1]:42424"` 以及 **FRP / DDNS 域名:端口**（如 `"frp.example.com:55555"`）。
- **添加即显示**：调用 `sync.addManualPeer(endpoint)` 时，Rust `PeerManager::register_manual_endpoint` 会**立即**在设备表中生成一条 `isManual = true` 的占位记录（初始名称为 `映射节点 (host:port)`），此时立即调用 `sync.getActivePeers()` 即可在 UI 的 `PeerDevices` 列表中看到该节点并对其执行**「配对」**或**「删除」**。
- **未配对状态下的 TCP 双向探测 (`MSG_HEARTBEAT`)**：添加映射节点时（及周期性扫描时），Rust 后台线程自动通过映射后的 TCP 端口向对端发送基于引导密钥加密的 `MSG_HEARTBEAT` 探测帧；对端收到后即使尚未配对也会回传其 `DiscoveryBeacon`，本端自动将占位节点原地升级为对端真实的 `deviceId`、`deviceName`、`deviceType`，同时**严格保留映射后的外部域名/IP 与外部端口**（绝不会被对端的内网端口覆盖）。

```kotlin
// 1. 添加端口映射节点（支持 IP:Port、纯 IP 或 FRP/DDNS 域名:端口）
sync.addManualPeer("frp.example.com:55555")

// 2. 立即刷新在线/映射设备列表（0 延迟拿到新添加的 isManual = true 节点）
val peersNow: List<PeerInfo> = sync.getActivePeers()

// 3. 延迟 400ms~1000ms 后再次刷新，即可看到 TCP MSG_HEARTBEAT 探测升级后的真实设备名与类型
delay(500)
val peersProbed: List<PeerInfo> = sync.getActivePeers()

// 4. 删除映射节点（支持传入 "host:port"、"host" 或解析后的 peer.deviceId）
// 调用后会同步从 PeerManager 的活跃设备列表中移除该节点并断开其连接池
sync.removeManualPeer("frp.example.com:55555")
// 或直接传入 PeerInfo.deviceId：
sync.removeManualPeer(peer.deviceId)

// 5. 获取所有已配置的静态映射地址字符串列表
val manualEndpoints: List<String> = sync.getManualPeers()
```

#### 3) 剪贴板零拷贝广播与连接测试

```kotlin
// 向所有在线已配对节点及端口映射节点并发推送加密剪贴板（内置 LoopbackFilter 防回环）
val reachedPeerCount: Int = sync.broadcastClipboard(text = "复制的文本", contentType = "text")

// 测试与指定节点的端到端加密握手延迟（返回毫秒数，失败返回 -1）
val rttMs: Int = sync.testPeer("frp.example.com:55555")
```

---

### 4.4 单流 TCP 随机 PIN 配对与双向解绑

#### 1) 作为发起方（主动点击某台设备发起配对）

```kotlin
// 生成 6 位随机数字 PIN 展示在本机屏幕上
val randomPin = "%06d".format( kotlin.random.Random.nextInt(100000, 999999) )

// 在协程中发起单流 TCP 握手（支持局域网 IP:Port 与 FRP/DDNS 域名:端口）
val result: PairResult = sync.requestPair(
    peerAddr = "${peer.ip}:${peer.syncPort}",
    pin = randomPin,
    timeoutSecs = 60
)

if (result.success) {
    // Rust 内部已通过 resolve_manual_peer_from_pair 自动将映射节点关联至真实 responderDeviceId
    // 并自动将引擎密钥切换为协商生成的 64 位 Hex 长期主密钥 (result.longTermKey)
    val keyToPersist = result.longTermKey ?: randomPin
    preferences.pairingPin = keyToPersist
    preferences.setDevicePairedInfo(result.responderDeviceId, result.responderDeviceName, peer.deviceType, true)
    sync.addPairedDevice(result.responderDeviceId)
} else {
    // result.errorCode: 1 = 对方拒绝, 2 = 对方输入 PIN 错误, 3 = 超时, -1 = 网络错误
    println("配对失败: ${result.errorMessage}")
}
```

#### 2) 作为接收方（收到远端配对请求弹窗确认）

通过 `sync.registerCallback(callback)` 监听远端事件：

```kotlin
sync.registerCallback(object : MuClipSyncCallback {
    override fun onClipboardReceived(deviceId: String, deviceName: String, content: String, contentType: String) {
        if (contentType == "system/ping") return
        core.addHistory(content)
        // 更新 UI 或写入系统剪贴板
    }

    override fun onPairRequestReceived(requestId: String, fromDeviceId: String, fromDeviceName: String, clientIp: String) {
        // 弹出对话框提示用户输入对方屏幕上显示的 6 位随机 PIN
        showPairDialog(requestId, fromDeviceName, clientIp)
    }

    override fun onPairSuccess(fromDeviceId: String, fromDeviceName: String, clientIp: String, pin: String) {
        // 握手成功！pin 参数即为双方通过 X25519 + HKDF 协商出的 64 位 Hex 长期主密钥
        preferences.pairingPin = pin
        preferences.setDevicePairedInfo(fromDeviceId, fromDeviceName, "配对设备", true)
        sync.addPairedDevice(fromDeviceId)
        sync.setPairingPin(pin)
    }

    override fun onPeerUnpaired(deviceId: String) {
        // 对端主动解除了配对，Rust 服务端已将其从白名单移除
        // ⚠️ 注意：此处切勿再次调用 sync.removePairedDevice(deviceId)，否则会向对端回发解绑通知造成死循环！
        preferences.setDevicePaired(deviceId, false)
    }

    override fun onFileOffer(transferId: String, fromDeviceId: String, fromDeviceName: String, fileName: String, fileSize: Long) {}
    override fun onFileProgress(transferId: String, bytesTransferred: Long, totalBytes: Long, speedBps: Long, isSend: Boolean) {}
    override fun onFileCompleted(transferId: String, filePath: String, isSend: Boolean, success: Boolean, errorMsg: String) {}
})

// 当用户在弹窗中输入 6 位 PIN 并点击“确认配对”时调用：
// 返回值：0 = 成功, 1 = 请求已过期, 2 = PIN 码错误, -1 = 异常
val status: Int = sync.respondPair(requestId = reqId, pin = userInputPin, accept = true)
```

---

### 4.5 统一 Rust 原生加密文件互传 (`sender.rs` / `receiver.rs`)

应用层（Android Kotlin / Windows C#）**无需执行任何密钥派生或 AEAD 加解密逻辑**。Rust 核心在 `MuClipSyncEngine::start`、`set_pairing_pin` 以及 ECDH 配对完成时统一保存唯一的 32 字节 `session_key`，收发双方完全复用同一套 Rust 原生 `sender.rs` 与 `receiver.rs`（128 KiB 内存池分块 + XChaCha20-Poly1305 原地 AEAD + SHA-256 全文件校验）。

#### 1) 发送文件（SAF `Uri` 原生文件描述符 `fd:<raw_fd>` 零缓存直传）

在 Android 上通过 `contentResolver.openFileDescriptor(uri, "r")` 打开只读描述符并调用 `detachFd()`，将 `"fd:$detachedFd"` 与真实文件名直接交给 `sync.sendFile`，Rust `sender.rs` 会直接通过 `File::from_raw_fd` 流式读取并自动关闭描述符，全程零磁盘缓存：

```kotlin
val (fileName, fileSize) = AndroidStorageUtils.getFileMetaFromUri(context, safUri)

// 从 SAF 获取只读文件描述符并移交所有权给 Rust sender.rs
val pfd = context.contentResolver.openFileDescriptor(safUri, "r")
    ?: throw IllegalStateException("无法读取所选文件")
val detachedFd = pfd.detachFd()

// 直接调用 Rust 发送接口（支持 IP:Port、纯 IP 默认 42424 或 FRP/DDNS 域名:端口）
val transferId = sync.sendFile(
    peerAddr = "${targetDevice.ip}:${targetDevice.syncPort}",
    filePath = "fd:$detachedFd",
    displayName = fileName
)
```

#### 2) 接收文件（Rust `receiver.rs` 全自动接收与完整性校验）

启动服务时调用 `sync.setFileSaveDir(stagingDir.absolutePath)` 配置接收暂存目录。当对端发来文件时，Rust `SyncServer` 直接交由 `receiver.rs` (`handle_incoming_file_stream`) 执行 128 KiB 分块原地解密、写入 `.tmp`、校验分块数与 SHA-256 摘要并原子重命名，Kotlin 只需在 `MuClipSyncCallback` 中监听进度与完成通知：

```kotlin
override fun onFileOffer(
    transferId: String,
    fromDeviceId: String,
    fromDeviceName: String,
    fileName: String,
    fileSize: Long
) {
    // 收到文件传输开始通知，在 UI 列表中创建接收任务卡片
}

override fun onFileProgress(
    transferId: String,
    bytesTransferred: Long,
    totalBytes: Long,
    speedBps: Long,
    isSend: Boolean
) {
    // Rust 发送/接收每 250ms 回调一次实时进度与速率 (B/s)
}

override fun onFileCompleted(
    transferId: String,
    filePath: String,
    isSend: Boolean,
    success: Boolean,
    errorMsg: String
) {
    if (!isSend && success && filePath.isNotEmpty()) {
        // 将校验通过的暂存文件发布到系统公共「Download/MuClip」目录并弹出通知
        val sourceFile = File(filePath)
        val publicPath = AndroidStorageUtils.publishToPublicDownload(context, sourceFile, sourceFile.name)
    }
}
```

---

## 5. JNI 底层接口全量速查 (`MuClipNative.kt`)

所有 JNI 原始函数声明位于 `com.muclip.core.MuClipNative`（对应 Rust 源码 `src/ffi/jni_direct/`）：

| 分类 | JNI 方法签名 (`MuClipNative`) | 说明 |
| :--- | :--- | :--- |
| **内存池** | `nativeAcquireBuffer(minCapacity: Long, outInfo: LongArray): ByteBuffer?` | 租借堆外 `DirectByteBuffer`，`outInfo` 填充 `[leaseId, capacity, rawPtr]` |
| | `nativeReleaseBuffer(leaseId: Long): Boolean` | 归还租借的堆外缓冲区 |
| | `nativeWrapDirectBuffer(rawPtr: Long, capacity: Long): ByteBuffer?` | 将裸指针包装为 `DirectByteBuffer` |
| **核心引擎** | `nativeInit(dbPath: String): Long` | 初始化 SQLite + LRU 热缓存引擎，返回 `handle` |
| | `nativeInitInMemory(): Long` | 初始化纯内存数据库引擎 |
| | `nativeClose(handle: Long)` | 刷盘并释放核心引擎句柄 |
| **历史记录** | `nativeAddHistoryZeroCopy(handle: Long, bufferPtr: Long, length: Int): Long` | 零拷贝写入剪贴板历史（自动统计字符/行/字节/类型并去重） |
| | `nativeQueryHistoryZeroCopy(handle: Long, limit: Int, outBufferPtr: Long, outCapacity: Int): Int` | 二进制格式查询最近历史记录 |
| | `nativeSearchHistoryZeroCopy(handle: Long, queryPtr: Long, queryLen: Int, limit: Int, outBufferPtr: Long, outCapacity: Int): Int` | 二进制格式搜索历史记录 |
| | `nativeDeleteHistory(handle: Long, id: Long): Int` | 按 ID 删除单条历史 (`0` = 成功) |
| | `nativeClearHistory(handle: Long): Int` | 清空全部历史记录 (`0` = 成功) |
| | `nativeCleanupHistory(handle: Long, days: Int): Int` | 清理早于 `days` 天的历史，返回清理条数 |
| **常用语** | `nativeAddPhraseZeroCopy(handle: Long, bufferPtr: Long, length: Int): Long` | 零拷贝添加常用语 |
| | `nativeQueryPhrasesZeroCopy(handle: Long, outBufferPtr: Long, outCapacity: Int): Int` | 二进制格式查询常用语列表 |
| **内容分析** | `nativeAnalyzeContentZeroCopy(textPtr: Long, textLen: Int, outBufferPtr: Long, outCapacity: Int): Int` | 二进制格式返回字符数、行数、字节数、类型与预览 |
| | `nativeFormatPreviewZeroCopy(textPtr: Long, textLen: Int, maxChars: Int, outBufferPtr: Long, outCapacity: Int): Int` | 零拷贝生成单行摘要预览 |
| **安全配置** | `nativeSetConfig(handle: Long, key: String, value: String): Int` | 写入 SQLite `secure_config` 键值 |
| | `nativeGetConfig(handle: Long, key: String): String?` | 读取 SQLite `secure_config` 键值 |
| **同步与发现** | `nativeStartSync(deviceId: String, deviceName: String, deviceType: String, syncPort: Int, pairingPin: String): Long` | 启动 P2P 同步与发现引擎，返回 `syncHandle` |
| | `nativeStopSync(syncHandle: Long)` | 停止并销毁同步引擎 |
| | `nativeBroadcastClipboardZeroCopy(syncHandle: Long, bufferPtr: Long, length: Int, contentType: String): Int` | 零拷贝向所有已配对及映射节点加密广播剪贴板 |
| | `nativeGetActivePeersZeroCopy(syncHandle: Long, outBufferPtr: Long, outCapacity: Int): Int` | 二进制格式获取所有在线及外部端口映射节点 (`PeerInfo`) |
| | `nativeGetAllPeersZeroCopy(syncHandle: Long, outBufferPtr: Long, outCapacity: Int): Int` | 二进制格式获取所有已知节点（含离线节点与映射节点） |
| | `nativeSetAutoDiscovery(syncHandle: Long, enabled: Boolean): Int` | 开启/关闭后台周期性 UDP/mDNS 广播 |
| | `nativeIsAutoDiscovery(syncHandle: Long): Boolean` | 查询自动发现开关状态 |
| | `nativeTriggerScan(syncHandle: Long): Int` | 立即触发一次全网卡 UDP 广播与 TCP 映射端口探测 |
| **端口映射** | `nativeAddManualPeer(syncHandle: Long, peerAddr: String): Int` | 添加映射节点（立即生成 `PeerInfo` 并启动 TCP `MSG_HEARTBEAT` 探测） |
| | `nativeRemoveManualPeer(syncHandle: Long, peerAddr: String): Int` | 按 `"host:port"`、`"host"` 或 `deviceId` 移除映射节点 |
| | `nativeGetManualPeersZeroCopy(syncHandle: Long, outBufferPtr: Long, outCapacity: Int): Int` | 二进制格式获取已配置的静态映射地址列表 |
| **配对与测试** | `nativeRequestPairZeroCopy(syncHandle: Long, peerAddr: String, pin: String, timeoutSecs: Int, outBufferPtr: Long, outCapacity: Int): Int` | 发起单流 TCP 随机 PIN 配对，二进制格式返回 `PairResult` |
| | `nativeRespondPair(syncHandle: Long, requestId: String, pin: String, accept: Boolean): Int` | 响应收到的配对请求 (`0`=成功, `1`=过期, `2`=PIN错误) |
| | `nativeAddPairedDevice(syncHandle: Long, deviceId: String): Int` | 将设备 ID 加入已配对白名单 |
| | `nativeRemovePairedDevice(syncHandle: Long, deviceId: String): Int` | 解除设备配对并向对端发送解绑通知 |
| | `nativeTestPeer(syncHandle: Long, peerAddr: String): Int` | 测试端到端加密连通性，返回 RTT 毫秒数 |
| | `nativeRegisterSyncCallback(syncHandle: Long, callback: MuClipSyncCallback): Int` | 注册全局异步事件回调 |
| **原地加解密** | `nativeEncryptInPlace(key: ByteArray, buffer: ByteArray, plaintextLength: Int, nonce: ByteArray, aad: ByteArray): Int` | 原地 `XChaCha20-Poly1305` 加密（零堆分配） |
| | `nativeDecryptInPlace(key: ByteArray, buffer: ByteArray, ciphertextAndTagLength: Int, nonce: ByteArray, aad: ByteArray): Int` | 原地 `XChaCha20-Poly1305` 解密与 Tag 校验 |
| | `nativeDeriveChunkNonce(fileNonce: ByteArray, chunkIndex: Long, outNonce: ByteArray): Int` | 原地派生 24 字节分块 Nonce |
| | `nativeBuildChunkAad(fileIdBytes: ByteArray, chunkIndex: Long, chunkLength: Int, totalFileSize: Long, outAad: ByteArray): Int` | 原地构造 57 字节文件分块上下文 AAD |

---

## 6. 生命周期与关键注意事项

1. **禁止将普通局域网配对设备注册为 `addManualPeer`**：
   - `addManualPeer` 专用于 **外部端口映射 / 跨网段静态节点**（会将节点标记为 `isManual = true` 并常驻于 `getActivePeers()` 中）。普通局域网设备只需调用 `addPairedDevice(deviceId)`，由 mDNS / UDP 42110 自动发现维护在线状态。
2. **禁止在 `onPeerUnpaired` 回调中反向调用 `removePairedDevice`**：
   - 当对端主动解除配对时，Rust `SyncServer` 已自动将对端移出配对白名单并触发 `onPeerUnpaired(deviceId)`。此时 Kotlin 侧只需更新本地 `SharedPreferences` 与 UI 状态，切勿再调用 `sync.removePairedDevice(deviceId)`。
3. **Android 14+ (targetSdk 34+) 前台服务启动时机**：
   - 切勿在 `Application.onCreate()` 中直接调用 `startForegroundService`，否则在 Android 14+ 后台拉起时会抛出 `ForegroundServiceStartNotAllowedException`。应在 `Application.onCreate()` 中完成 `MuClipCore.open` 与 `MuClipSync.start`，并在 `MainActivity` 进入前台后启动 `ClipboardSyncService`。
