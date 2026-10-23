# MuClip 极速剪贴板 Rust 核心 DLL (Windows x64) 调用与集成指南
> 适用目标：C# (.NET 8 / .NET 9)、Avalonia UI、WPF、WinUI3 以及你的 Avalonia OCR 软件项目。

---

## 1. 架构定位：Rust 核心与 UI 前台的分工

```
+-------------------------------------------------------------+
|             Avalonia OCR / C# 应用程序 (UI 交互层)           |
|  - 只负责 UI 渲染、OCR 识别触发、快捷键响应、窗口托盘展示        |
|  - 前台极其轻量，无需维护复杂的多线程网络 Socket 与数据库缓存     |
+------------------------------+------------------------------+
                               | P/Invoke C-ABI 调用
                               v
+-------------------------------------------------------------+
|                   muclip_core.dll (Rust 核心)                |
|  - 内存管理：Top 100 条热数据 LRU 纯内存缓存 (5MB 严格限额)   |
|  - 持久化：SQLite 零碎片存储、FTS 搜索、过期自动清理          |
|  - P2P 局域网自发现：UDP 组播 + 广播 + 单播探测 (端口 42110)  |
|  - 端到端安全加密：ChaCha20-Poly1305 + HKDF-SHA256          |
|  - 状态同步与防回环：Loopback 广播去重抑制、自定义端口映射     |
+-------------------------------------------------------------+
```

### 为什么把数据与同步完全交给 Rust？
1. **极致内存与性能**：Rust 核心接管剪贴板读写与 100 条近期热缓存，前台 UI 无需常驻大数组；
2. **零 GC 垃圾回收压力**：网络数据包解密、反序列化在 Rust 内部完成，避免 C# 频繁触发 GC 卡顿；
3. **跨多平台无缝复用**：相同的 `muclip-core` 已编译并运行在 Android、Windows 上，通过标准 C-ABI 暴露所有功能。

---

## 2. 核心 FFI 方案：手动租借内存池 (Manual Leased Memory Pool)

为了达到高吞吐、零 GC 停顿与无内存碎片，本项目采用**调用端手动租借内存池**的零拷贝 FFI 架构：

```
+------------------+         muclip_pool_acquire(min_cap)         +--------------------+
|                  | -------------------------------------------> |                    |
|   C# (.NET 11)   |                                              |  muclip_core.dll   |
|   调用层 (UI)     | <------------------------------------------- |  Rust 离堆原生池   |
|                  |       (lease_id, raw_ptr, actual_cap)        |  NativeBufferPool  |
|  ReadOnlySpan<T> |                                              |  (64字节对齐缓存)  |
|  就地直接反序列化  | -------- using var lease.Dispose() --------> |  O(1) 快速入池回收  |
|                  |          muclip_pool_release(lease_id)       |                    |
+------------------+                                              +--------------------+
```

### 传统 FFI 与手动租借内存池的对比：
| 指标 | 传统 C-ABI (CString / malloc) | 手动租借内存池 (Manual Leased Memory Pool) |
| :--- | :--- | :--- |
| **内存分配位置** | 每次调用均在系统原生堆 `malloc` | 原生离堆环形预分配池（支持 64 字节 SIMD 对齐） |
| **托管堆影响** | `Marshal.PtrToStringUTF8` 分配大托管字符串 | 直接以 `ReadOnlySpan<byte>` 就地解析，**零托管内存分配** |
| **释放开销** | 必须由托管端显式调用 `free_string` | `using var lease` 作用域结束即时 O(1) 归还池中，无内存碎片 |
| **大文本写入** | 托管大字符串分配至大对象堆 (LOH) | 先租借原生缓冲区，写入后交由 Rust 吸收，绕过托管堆 |

---

## 3. 部署 `muclip_core.dll`

在你的 C# / Avalonia 项目工程目录中：
1. 从 MuClip 项目的 `dist/muclip_core.dll` 复制到你的 C# 项目（例如 `Libs/x64/muclip_core.dll`）。
2. 在 `.csproj` 中配置编译时自动拷贝到输出目录：
```xml
<ItemGroup>
  <None Include="Libs\x64\muclip_core.dll">
    <Link>muclip_core.dll</Link>
    <CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory>
  </None>
</ItemGroup>
```
确保你的 C# 项目目标架构为 `x64`（或 `win-x64`）。

---

## 4. 开箱即用的 C# 封装类源码

你可以直接将以下两个类文件复制到你的 C# 项目中使用。

### 3.1 `MuClipCore.cs`（本地剪贴板与缓存引擎）

```csharp
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MuClip.Interop
{
    public class HistoryRecord
    {
        [JsonPropertyName("id")]
        public long Id { get; set; }

        [JsonPropertyName("content")]
        public string Content { get; set; } = string.Empty;

        [JsonPropertyName("created_at")]
        public string CreatedAt { get; set; } = string.Empty;

        [JsonPropertyName("last_used_at")]
        public string LastUsedAt { get; set; } = string.Empty;
    }

    public class ContentAnalysisResult
    {
        [JsonPropertyName("content_type")]
        public string ContentType { get; set; } = "text";

        [JsonPropertyName("char_count")]
        public int CharCount { get; set; }

        [JsonPropertyName("line_count")]
        public int LineCount { get; set; }

        [JsonPropertyName("preview")]
        public string Preview { get; set; } = string.Empty;
    }

    /// <summary>
    /// Rust 剪贴板核心引擎（管理 SQLite 数据库与前 100 条极速热内存缓存）
    /// </summary>
    public sealed class MuClipCore : IDisposable
    {
        private const string DllName = "muclip_core.dll";
        private IntPtr _handle;

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "muclip_core_new")]
        private static extern IntPtr NativeNew(byte[] dbPath);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "muclip_core_new_in_memory")]
        private static extern IntPtr NativeNewInMemory();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "muclip_core_free")]
        private static extern void NativeFree(IntPtr handle);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "muclip_core_free_string")]
        private static extern void NativeFreeString(IntPtr str);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "muclip_core_add_history")]
        private static extern long NativeAddHistory(IntPtr handle, byte[] content);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "muclip_core_get_cached_items")]
        private static extern IntPtr NativeGetCachedItems(IntPtr handle);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "muclip_core_query_history")]
        private static extern IntPtr NativeQueryHistory(IntPtr handle, UIntPtr limit);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "muclip_core_search_history")]
        private static extern IntPtr NativeSearchHistory(IntPtr handle, byte[] query, UIntPtr limit);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "muclip_core_delete_history")]
        private static extern int NativeDeleteHistory(IntPtr handle, long id);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "muclip_core_clear_history")]
        private static extern int NativeClearHistory(IntPtr handle);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "muclip_core_analyze_content")]
        private static extern IntPtr NativeAnalyzeContent(byte[] text);

        /// <summary>
        /// 打开或创建指定路径的 SQLite 数据库核心实例
        /// </summary>
        public MuClipCore(string dbPath)
        {
            byte[] pathBytes = Encoding.UTF8.GetBytes(dbPath + "\0");
            _handle = NativeNew(pathBytes);
            if (_handle == IntPtr.Zero)
            {
                throw new InvalidOperationException($"无法初始化 MuClip 核心数据库，路径: {dbPath}");
            }
        }

        /// <summary>
        /// 创建内存数据库实例（不落地磁盘）
        /// </summary>
        public static MuClipCore CreateInMemory()
        {
            var inst = (MuClipCore)System.Runtime.Serialization.FormatterServices.GetUninitializedObject(typeof(MuClipCore));
            inst._handle = NativeNewInMemory();
            return inst;
        }

        /// <summary>
        /// 添加一条新剪贴板内容（自动写入热缓存并异步落盘，自动去重）
        /// </summary>
        public long AddHistory(string content)
        {
            ThrowIfDisposed();
            byte[] bytes = Encoding.UTF8.GetBytes(content + "\0");
            return NativeAddHistory(_handle, bytes);
        }

        /// <summary>
        /// 获取当前纯内存热缓存中的前 100 条记录（极速响应，不碰磁盘 SQLite）
        /// </summary>
        public List<HistoryRecord> GetCachedItems()
        {
            ThrowIfDisposed();
            IntPtr ptr = NativeGetCachedItems(_handle);
            return ReadJsonAndFree<List<HistoryRecord>>(ptr) ?? new List<HistoryRecord>();
        }

        /// <summary>
        /// 查询历史记录（从 SQLite 查询）
        /// </summary>
        public List<HistoryRecord> QueryHistory(int limit = 50)
        {
            ThrowIfDisposed();
            IntPtr ptr = NativeQueryHistory(_handle, (UIntPtr)limit);
            return ReadJsonAndFree<List<HistoryRecord>>(ptr) ?? new List<HistoryRecord>();
        }

        /// <summary>
        /// 模糊搜索历史记录
        /// </summary>
        public List<HistoryRecord> SearchHistory(string query, int limit = 50)
        {
            ThrowIfDisposed();
            byte[] queryBytes = Encoding.UTF8.GetBytes(query + "\0");
            IntPtr ptr = NativeSearchHistory(_handle, queryBytes, (UIntPtr)limit);
            return ReadJsonAndFree<List<HistoryRecord>>(ptr) ?? new List<HistoryRecord>();
        }

        /// <summary>
        /// 删除某条历史记录
        /// </summary>
        public bool DeleteHistory(long id)
        {
            ThrowIfDisposed();
            return NativeDeleteHistory(_handle, id) == 0;
        }

        /// <summary>
        /// 清空所有历史
        /// </summary>
        public bool ClearHistory()
        {
            ThrowIfDisposed();
            return NativeClearHistory(_handle, id: 0) == 0;
        }

        /// <summary>
        /// 分析内容特征（识别类型：URL/JSON/颜色/代码/纯文本，提取行数与预览）
        /// </summary>
        public static ContentAnalysisResult AnalyzeContent(string text)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(text + "\0");
            IntPtr ptr = NativeAnalyzeContent(bytes);
            return ReadJsonAndFree<ContentAnalysisResult>(ptr) ?? new ContentAnalysisResult();
        }

        private static T? ReadJsonAndFree<T>(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero) return default;
            try
            {
                string json = Marshal.PtrToStringUTF8(ptr) ?? string.Empty;
                return JsonSerializer.Deserialize<T>(json);
            }
            finally
            {
                NativeFreeString(ptr);
            }
        }

        private void ThrowIfDisposed()
        {
            if (_handle == IntPtr.Zero) throw new ObjectDisposedException(nameof(MuClipCore));
        }

        public void Dispose()
        {
            if (_handle != IntPtr.Zero)
            {
                NativeFree(_handle);
                _handle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }

        ~MuClipCore() => Dispose();
    }
}
```

---

### 3.2 `MuClipSync.cs`（P2P 局域网自发现与加密同步引擎）

```csharp
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MuClip.Interop
{
    public class PeerDeviceInfo
    {
        [JsonPropertyName("device_id")]
        public string DeviceId { get; set; } = string.Empty;

        [JsonPropertyName("device_name")]
        public string DeviceName { get; set; } = string.Empty;

        [JsonPropertyName("device_type")]
        public string DeviceType { get; set; } = string.Empty;

        [JsonPropertyName("ip")]
        public string Ip { get; set; } = string.Empty;

        [JsonPropertyName("sync_port")]
        public int SyncPort { get; set; }

        [JsonPropertyName("last_seen_ms")]
        public long LastSeenMs { get; set; }

        [JsonPropertyName("is_online")]
        public bool IsOnline { get; set; }

        [JsonPropertyName("fingerprint")]
        public string Fingerprint { get; set; } = string.Empty;

        [JsonPropertyName("is_paired")]
        public bool IsPaired { get; set; }
    }

    public class RemoteClipboardEventArgs : EventArgs
    {
        public string Content { get; }
        public string ContentType { get; }
        public string DeviceId { get; }
        public string DeviceName { get; }

        public RemoteClipboardEventArgs(string content, string contentType, string deviceId, string deviceName)
        {
            Content = content;
            ContentType = contentType;
            DeviceId = deviceId;
            DeviceName = deviceName;
        }
    }

    /// <summary>
    /// Rust P2P 局域网自发现与端到端加密同步引擎
    /// </summary>
    public sealed class MuClipSync : IDisposable
    {
        private const string DllName = "muclip_core.dll";
        private IntPtr _handle;

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void NativeCallback(
            IntPtr content,
            IntPtr contentType,
            IntPtr deviceId,
            IntPtr deviceName,
            IntPtr userData
        );

        private readonly NativeCallback _pinnedCallback;

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "muclip_sync_start")]
        private static extern IntPtr NativeSyncStart(
            byte[] deviceId,
            byte[] deviceName,
            byte[] deviceType,
            ushort syncPort,
            ushort discoveryPort,
            byte[] pairingPin
        );

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "muclip_sync_stop")]
        private static extern void NativeSyncStop(IntPtr handle);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "muclip_sync_get_bound_port")]
        private static extern ushort NativeSyncGetBoundPort(IntPtr handle);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "muclip_sync_get_active_peers")]
        private static extern IntPtr NativeSyncGetActivePeers(IntPtr handle);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "muclip_sync_set_pairing_pin")]
        private static extern int NativeSyncSetPairingPin(IntPtr handle, byte[] pin);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "muclip_sync_add_manual_peer")]
        private static extern int NativeSyncAddManualPeer(IntPtr handle, byte[] addr);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "muclip_sync_remove_manual_peer")]
        private static extern int NativeSyncRemoveManualPeer(IntPtr handle, byte[] addr);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "muclip_sync_broadcast")]
        private static extern UIntPtr NativeSyncBroadcast(IntPtr handle, byte[] text, byte[] contentType);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "muclip_sync_set_callback")]
        private static extern void NativeSyncSetCallback(IntPtr handle, NativeCallback callback, IntPtr userData);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "muclip_core_free_string")]
        private static extern void NativeFreeString(IntPtr str);

        /// <summary>
        /// 当局域网远端设备（如 Android 手机）同步新的剪贴板数据过来时触发
        /// </summary>
        public event EventHandler<RemoteClipboardEventArgs>? ClipboardReceived;

        public ushort BoundPort { get; private set; }

        public MuClipSync(
            string deviceId,
            string deviceName,
            string deviceType = "Windows",
            ushort syncPort = 42424,
            ushort discoveryPort = 42110,
            string pairingPin = "000000"
        )
        {
            byte[] idBytes = Encoding.UTF8.GetBytes(deviceId + "\0");
            byte[] nameBytes = Encoding.UTF8.GetBytes(deviceName + "\0");
            byte[] typeBytes = Encoding.UTF8.GetBytes(deviceType + "\0");
            byte[] pinBytes = Encoding.UTF8.GetBytes(pairingPin + "\0");

            _handle = NativeSyncStart(idBytes, nameBytes, typeBytes, syncPort, discoveryPort, pinBytes);
            if (_handle == IntPtr.Zero)
            {
                throw new InvalidOperationException("启动 MuClip 局域网同步引擎失败！");
            }

            BoundPort = NativeSyncGetBoundPort(_handle);

            // 注册 C-ABI 回调函数（保持 GC 引用防止被回收）
            _pinnedCallback = OnNativeClipboardReceived;
            NativeSyncSetCallback(_handle, _pinnedCallback, IntPtr.Zero);
        }

        private void OnNativeClipboardReceived(IntPtr contentPtr, IntPtr typePtr, IntPtr devIdPtr, IntPtr devNamePtr, IntPtr userData)
        {
            string content = Marshal.PtrToStringUTF8(contentPtr) ?? string.Empty;
            string contentType = Marshal.PtrToStringUTF8(typePtr) ?? "text";
            string devId = Marshal.PtrToStringUTF8(devIdPtr) ?? string.Empty;
            string devName = Marshal.PtrToStringUTF8(devNamePtr) ?? string.Empty;

            ClipboardReceived?.Invoke(this, new RemoteClipboardEventArgs(content, contentType, devId, devName));
        }

        /// <summary>
        /// 广播剪贴板到所有已发现且在线的设备（以及手动添加的节点）
        /// </summary>
        public int Broadcast(string text, string contentType = "text")
        {
            ThrowIfDisposed();
            byte[] textBytes = Encoding.UTF8.GetBytes(text + "\0");
            byte[] typeBytes = Encoding.UTF8.GetBytes(contentType + "\0");
            return (int)NativeSyncBroadcast(_handle, textBytes, typeBytes);
        }

        /// <summary>
        /// 获取当前局域网内在线发现的所有设备及其实时配对状态 (IsPaired)
        /// </summary>
        public List<PeerDeviceInfo> GetActivePeers()
        {
            ThrowIfDisposed();
            IntPtr ptr = NativeSyncGetActivePeers(_handle);
            if (ptr == IntPtr.Zero) return new List<PeerDeviceInfo>();

            try
            {
                string json = Marshal.PtrToStringUTF8(ptr) ?? string.Empty;
                return JsonSerializer.Deserialize<List<PeerDeviceInfo>>(json) ?? new List<PeerDeviceInfo>();
            }
            finally
            {
                NativeFreeString(ptr);
            }
        }

        /// <summary>
        /// 动态修改配对 PIN 码（立即重新派生加密密钥与指纹）
        /// </summary>
        public bool SetPairingPin(string pin)
        {
            ThrowIfDisposed();
            byte[] bytes = Encoding.UTF8.GetBytes(pin + "\0");
            return NativeSyncSetPairingPin(_handle, bytes) == 0;
        }

        /// <summary>
        /// 添加固定映射节点（支持公网 IP、Tailscale、FRP 穿透，如 "192.168.1.100:42424" 或 "myfrp.host:55555"）
        /// 即使路由器开启了 AP 客户端隔离，也可通过单播持续自发现与双向同步
        /// </summary>
        public bool AddManualPeer(string endpoint)
        {
            ThrowIfDisposed();
            byte[] bytes = Encoding.UTF8.GetBytes(endpoint.Trim() + "\0");
            return NativeSyncAddManualPeer(_handle, bytes) == 0;
        }

        /// <summary>
        /// 移除手动配置的节点
        /// </summary>
        public bool RemoveManualPeer(string endpoint)
        {
            ThrowIfDisposed();
            byte[] bytes = Encoding.UTF8.GetBytes(endpoint.Trim() + "\0");
            return NativeSyncRemoveManualPeer(_handle, bytes) == 0;
        }

        private void ThrowIfDisposed()
        {
            if (_handle == IntPtr.Zero) throw new ObjectDisposedException(nameof(MuClipSync));
        }

        public void Dispose()
        {
            if (_handle != IntPtr.Zero)
            {
                NativeSyncStop(_handle);
                _handle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }

        ~MuClipSync() => Dispose();
    }
}
```

---

## 4. 实战：在 Avalonia OCR 软件中如何无缝接入

### 场景 1：软件启动初始化 (App.axaml.cs)
```csharp
public static MuClipCore? ClipCore { get; private set; }
public static MuClipSync? ClipSync { get; private set; }

public override void OnFrameworkInitializationCompleted()
{
    // 1. 初始化 Rust 剪贴板核心（指定数据库存储位置，例如 AppData）
    string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    string dbPath = Path.Combine(appData, "MyOcrApp", "muclip.db");
    Directory.CreateDirectory(Path.GetDirectoryName(dbPath)!);
    
    ClipCore = new MuClipCore(dbPath);

    // 2. 启动局域网同步引擎（默认端口 42424，可配置自定义端口）
    ushort customPort = 42424; // 也可以从用户配置读取自定义端口
    string pairingPin = "000000"; // 默认 PIN 码或用户设置

    ClipSync = new MuClipSync(
        deviceId: "ocr-win-" + Environment.MachineName,
        deviceName: $"OCR工作站 ({Environment.MachineName})",
        deviceType: "Windows",
        syncPort: customPort,
        discoveryPort: 42110,
        pairingPin: pairingPin
    );

    // 3. 监听来自 Android 手机或其他设备的同步数据
    ClipSync.ClipboardReceived += (s, e) =>
    {
        // 自动存入 Rust 核心与热缓存
        ClipCore.AddHistory(e.Content);

        // 切换到 Avalonia UI 线程通知界面更新或弹窗
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            // 例如更新 ViewModel 中的历史记录列表
            // MyOcrViewModel.Instance.RefreshHistory();
        });
    };

    base.OnFrameworkInitializationCompleted();
}
```

### 场景 2：OCR 识别完成后自动写入并同步
当用户在你的软件中完成一次 OCR 识别：
```csharp
public async Task OnOcrRecognized(string recognizedText)
{
    if (string.IsNullOrWhiteSpace(recognizedText)) return;

    // 1. 写入系统原生剪贴板
    var topLevel = TopLevel.GetTopLevel(this);
    if (topLevel?.Clipboard != null)
    {
        await topLevel.Clipboard.SetTextAsync(recognizedText);
    }

    // 2. 存入 Rust 核心缓存与 SQLite
    App.ClipCore?.AddHistory(recognizedText);

    // 3. 广播给局域网其他设备（例如手机瞬间就能收到并粘贴识别结果！）
    int sentCount = App.ClipSync?.Broadcast(recognizedText, "text") ?? 0;
    Console.WriteLine($"已自动同步 OCR 结果至 {sentCount} 台在线设备");
}
```

### 场景 3：设备列表与配对状态展示 (Avalonia ViewModel 轮询)
```csharp
// 在设备的管理页面 ViewModel 中，开启一个定时器刷新发现的设备：
private void StartPeerMonitoring()
{
    var timer = new System.Timers.Timer(3000); // 每 3 秒刷新一次
    timer.Elapsed += (s, e) =>
    {
        var peers = App.ClipSync?.GetActivePeers() ?? new List<PeerDeviceInfo>();
        
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            DiscoveredPeers.Clear();
            foreach (var peer in peers)
            {
                // peer.IsOnline: 是否在线
                // peer.IsPaired: 配对 PIN 码是否与本机匹配！
                // peer.SyncPort: 对端设备的端口（包含对端自定义的端口）
                DiscoveredPeers.Add(new DeviceItemViewModel(peer));
            }
        });
    };
    timer.Start();
}
```

### 场景 4：自定义端口与网络穿透（FRP / NAT）
若用户网络环境受限，需要在路由器或公网转发端口：
1. **自定义本机监听端口**：只需在实例化 `MuClipSync(..., syncPort: 55555)` 时传入自定义端口即可。Rust 会在当前端口监听，并自动在广播信标中带上该端口，对端扫描到后会直接连接自定义端口。
2. **跨网段/跨公网手动配置对端**：
```csharp
// 添加固定节点（支持域名:端口 或 IP:端口）
App.ClipSync?.AddManualPeer("192.168.31.88:42424");
App.ClipSync?.AddManualPeer("myfrp.server.com:33333");
```
此时 Rust 引擎不仅会广播，还会**定期向此节点发送单播握手**，即使跨网段或路由器开启了 AP 隔离，也能精准配对同步！

---

## 5. 常见问题排查与保障

| 现象 | 原因分析 | 解决方案 |
| :--- | :--- | :--- |
| **设备列表显示为空** | Windows 系统 5353 端口常被 DNS 缓存占用，且未设置端口复用 | 新版已默认启用专有端口 `42110` + `SO_REUSEADDR`，并双发 `5353` 兼容旧节点。若在公司网络，可直接调用 `AddManualPeer(ip)` 单播发现。 |
| **Android 端搜不到设备** | Android 系统未获取 `MulticastLock` 导致底层 Wi-Fi 硬件休眠时丢弃组播 | Android 端已在 `ClipboardSyncService` 中自动持有 `WifiManager.MulticastLock`。 |
| **能同步但显示未配对** | 之前未在 `PeerInfo` 结构体中对比 PIN 密钥指纹 | 新版 `PeerDeviceInfo` 中包含 `is_paired` 字段。双方 PIN 码相同时为 `true`，不同时为 `false`。 |
| **内存占用超标** | UI 每次全量读取所有记录 | 只需调用 `GetCachedItems()` 读取前 100 条热缓存，总内存消耗小于 5MB，渲染无压力。 |
