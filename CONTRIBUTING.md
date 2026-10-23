# 贡献指南

感谢愿意帮忙。这个项目是跨语言、跨平台的，提交前请先看完下面三节。

---

## 开发环境

| 依赖 | 版本 | 说明 |
| :--- | :--- | :--- |
| Rust | 1.85+（edition 2024） | `rustup component add rustfmt clippy` |
| Windows SDK / MSVC | 任意近期版本 | Windows 端 `cdylib` 链接 |
| Android NDK | r26+ | 仅编译 Android 目标时需要 |
| `cargo-ndk` | 最新 | `cargo install cargo-ndk` |

---

## 提交前的硬性要求

```powershell
cargo fmt --all
cargo clippy --all-targets -- -D clippy::correctness
cargo test
```

三条必须全绿。CI 会跑同样的命令，本地过了基本不会挂。

**新增功能的测试要求**

| 改动范围 | 需要补的测试 |
| :--- | :--- |
| `sync/protocol.rs` | 编解码往返 + 坏魔数 / 坏版本 / 截断 / 超长载荷 |
| `sync/crypto.rs` | HKDF 确定性、salt 敏感性、nonce 唯一性、标签篡改拒绝 |
| `sync/transport/` | 端点握手、配对成功与失败、错误 PIN、失败次数上限 |
| `sync/file_transfer/` | 端到端小文件 / 大文件、取消、连接中断 |
| `ffi/` | 导出函数的内存所有权与释放路径 |

对抗性测试不是"多写几个 assert"，而是**假设攻击者会改你的字节**。参考 `src/sync/crypto.rs` 里已有的用例写法。

---

## 代码约定

- **编辑器配置**：跟随 `rustfmt.toml`（若有）与默认 rustfmt；不做大范围纯格式 diff，会淹没真正的改动。
- **`unsafe` 必须有 `// SAFETY:` 注释**，说明为什么这些前置条件成立。FFI 层几乎全是 `unsafe`，这一条尤其重要。
- **错误不要 `unwrap()`**：库代码里出现 `unwrap()` 需要能证明不会 panic；`expect()` 要带上下文信息。
- **中文注释可以，但变量名、函数名、类型名一律英文。**
- **跨语言接口变更**：改了 `src/ffi/` 的签名，必须同步更新该函数的文档注释、README 的接口示例，以及调用方客户端，否则客户端会静默崩溃。

---

## 跨平台同步（重要）

改了 `src/` 下的 Rust 代码后，**两端都要重新编译**，否则 Windows 客户端与 Android 客户端会跑在不同版本的协议上：

```powershell
cd <repo>
cargo build --release

cargo ndk -t arm64-v8a -o <MuClip-Android>\app\src\main\jniLibs build --release
```

（`<repo>` 指本仓库根目录，`<MuClip-Android>` 指 Android 客户端的本地路径。）

协议一旦不兼容，帧头的 `Version` 字段要递增，并在 `SyncHeader::parse` 里保留明确的错误提示——不要静默降级处理，那会让排查变成噩梦。

---

## 提交信息

采用 Conventional Commits 风格，中英文均可：

```
feat(sync): 文件传输支持断点续传
fix(protocol): 修正 payload_len 未包含 tag 导致的对齐错误
test(crypto): 补充 nonce 复用拒绝用例
docs(readme): 修正 PK 配对描述为 SPAKE2
```

一个 commit 做一件事。格式化改动单独成一个 commit（例如 `style: cargo fmt --all`）。

---

## 分支与 PR

1. 从 `main` 拉分支：`feat/xxx`、`fix/xxx`、`docs/xxx`
2. PR 描述里写清：**改了什么、为什么、怎么验证的**
3. 涉及协议或加密的改动，请在 PR 里显式说明**是否向后兼容**
4. 若 CI 挂了，先本地复现；不要用 `--no-verify` 绕过 hook

---

## 文档改动同样欢迎

README 里的错误描述、过期截图、跑不通的命令行，都是有效的贡献。**文档里的技术描述必须是可验证的**——写"支持 100MB/s"就得给出复现命令与测试环境，写"已加密"就得能指出加密发生在哪一行。含糊的营销式描述会被 review 打回。

---

## 行为准则

技术上可以强硬，人际上必须礼貌。不接受人身攻击、歧视性言论、以及未经允许的他人隐私信息（真实 IP、内网拓扑、个人路径等）。

提交代码前请确认：**你的 diff 里没有硬编码的本地绝对路径、真实设备 ID、内网 IP、个人邮箱或明文密钥。** 这条是硬性要求。
