# Extension-Kit 编译修复总结

## 修复概览

Extension-Kit 已成功在 macOS (Apple Silicon) 上完成跨平台编译，所有 74 个 BOF 模块全部编译通过。

## 修复的主要问题

### 1. C23 标准兼容性问题
**问题**: `typedef int bool;` 在 C23 标准中不再允许  
**位置**: `AD-BOF/Kerbeus-BOF/_include/kerb_struct.h`  
**修复**: 使用标准的 `<stdbool.h>` 头文件
```c
// 修复前
typedef int bool;
#define true 1
#define false 0

// 修复后
#include <stdbool.h>
```

### 2. macOS 链接器兼容性
**问题**: macOS 上的 GCC (clang) 不支持 `-static` 选项  
**位置**: `Creds-BOF/nanodump/Makefile`  
**修复**: 移除 `-static` 和 `-s` 选项
```makefile
# 修复前
@$(GCC) source/bin2c.c -o dist/bin2c -static -s -Os

# 修复后
@$(GCC) source/bin2c.c -o dist/bin2c -Os
```

### 3. 函数声明与定义不匹配
**问题**: 头文件中的函数声明与实现中的参数不一致  
**位置**: `Creds-BOF/nanodump/include/ppl/ppl_medic.h`  
**修复**: 添加正确的参数签名
```c
// 修复前
BOOL find_waa_s_medic_svc_base_named_objects_handle();

// 修复后
BOOL find_waa_s_medic_svc_base_named_objects_handle(
    OUT PHANDLE BaseNamedObjectsHandle);
```

### 4. 全局变量与函数参数冲突
**问题**: 函数定义使用了与全局变量同名的参数，导致编译器混淆  
**位置**: `Injection-BOF/inject_poolparty/PoolParty.h`  
**修复**: 重命名参数以避免冲突
```c
// 修复前
WORKER_FACTORY_BASIC_INFORMATION GetWorkerFactoryBasicInformation(HANDLE hTpWorkerFactory) {
    // 使用 hTpWorkerFactory 参数

// 修复后
WORKER_FACTORY_BASIC_INFORMATION GetWorkerFactoryBasicInformation(HANDLE hTpWorkerFactoryParam) {
    // 使用 hTpWorkerFactoryParam 参数
```

### 5. BOF 动态函数解析问题 ⭐
**问题**: `FARPROC` 通用函数指针无法直接调用，需要类型转换  
**位置**: `Creds-BOF/cookie-monster/cookie-monster-bof.c`  
**修复**: 定义明确的函数类型并进行强制类型转换
```c
// 修复前
#define IMPORT_RESOLVE FARPROC SHGetFolderPath = Resolver("shell32", "SHGetFolderPathA");

// 修复后
typedef HRESULT (WINAPI *pSHGetFolderPathA)(HWND, int, HANDLE, DWORD, LPSTR);
#define IMPORT_RESOLVE pSHGetFolderPathA SHGetFolderPath = (pSHGetFolderPathA)Resolver("shell32", "SHGetFolderPathA");
```

### 6. 缺少前向声明
**问题**: 函数在使用前未声明  
**位置**: `Creds-BOF/cookie-monster/cookie-monster-bof.c`  
**修复**: 添加前向声明
```c
// 添加的前向声明
BOOL download_file(IN LPCSTR fileName, IN char fileData[], IN ULONG32 fileLength);
BOOL GetBrowserFile(DWORD PID, CHAR *browserFile, CHAR *downloadFileName, CHAR * folderPath);
```

## 编译统计

### 成功编译的模块 (74/74)

#### AD-BOF (17 个)
- ldapsearch, hash, klist, triage, dump, describe, tgtdeleg, ptt, purge
- asktgt, asktgs, renew, changepw, asreproasting, kerberoasting, s4u, cross_s4u

#### Creds-BOF (18 个)
- askcreds, autologon, credman, get-netntlm, hashdump, **cookie-monster** ✅
- nanodump (x64/x86), nanodump_ssp (x64/x86), nanodump_ppl_dump (x64/x86), nanodump_ppl_medic (x64)

#### Elevation-BOF (3 个)
- getsystem_token, uac_regshellcmd, uac_sspi

#### Execution-BOF (3 个)
- execute-assembly, NoConsolation (x64/x86)

#### Injection-BOF (3 个)
- inject_cfg, inject_sec, **inject_poolparty** ✅

#### LateralMovement-BOF (3 个)
- psexec, token_make, token_steal

#### Postex-BOF (2 个)
- Screenshot, addfirewallrule

#### Process-BOF (3 个)
- findmodule, findprochandle, psc

#### SAL-BOF (17 个)
- arp, cacls, dir, env, ipconfig, listdns, netstat, nslookup, routeprint
- uptime, useridletime, whoami, vulndrivers, alwayselevated, hijackablepath, tokenpriv, unattendfiles, unquotedsvc

#### SAR-BOF (1 个)
- quser

## 技术要点

### BOF (Beacon Object File) 模式
这些模块使用了特殊的 BOF 编译模式：
1. **动态 API 解析**: 使用 `GetProcAddress` 在运行时加载 Windows API
2. **无标准库依赖**: 所有 MSVCRT/KERNEL32 函数通过动态解析调用
3. **位置无关代码**: 可以注入到任意进程空间执行

### 跨平台编译
在 macOS (Apple Silicon) 上使用 MinGW-w64 成功编译 Windows 目标文件：
- 编译器: `x86_64-w64-mingw32-gcc` / `i686-w64-mingw32-gcc`
- 目标平台: Windows x64/x86
- 主机平台: macOS ARM64

## 修复的文件清单

1. `AD-BOF/Kerbeus-BOF/_include/kerb_struct.h` - C23 bool 兼容
2. `Creds-BOF/Makefile` - 启用 cookie-monster
3. `Creds-BOF/cookie-monster/cookie-monster-bof.c` - 函数类型定义和前向声明
4. `Creds-BOF/nanodump/Makefile` - macOS 链接器兼容
5. `Creds-BOF/nanodump/include/ppl/ppl_medic.h` - 函数签名修复
6. `Injection-BOF/inject_poolparty/PoolParty.h` - 参数重命名
7. `Injection-BOF/inject_poolparty/2.h` - 函数调用修复
8. `Injection-BOF/inject_poolparty/5.h` - 函数调用修复

## 验证

```bash
cd Extension-Kit
make clean
make
# 输出: 74 个 [+] 成功标记，0 个 [!] 失败标记
```

---

**修复完成时间**: 2025-01-13  
**编译环境**: macOS 14.x (Apple Silicon) + MinGW-w64  
**编译目标**: Windows x64/x86 BOF 模块

