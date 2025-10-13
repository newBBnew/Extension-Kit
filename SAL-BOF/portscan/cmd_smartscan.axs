// SmartPortScan - 智能端口扫描命令

Command("smartscan", {
    cmd: {
        description: "Smart TCP port scanner with CIDR support",
        help: `
智能端口扫描工具

用法:
  smartscan <target> [options]

参数:
  <target>     目标IP或CIDR (如: 192.168.1.1 或 192.168.1.0/24)
  [options]    扫描选项:
               1           - 快速扫描 (10个高优先级端口)
               2           - 标准扫描 (25个端口, 默认)
               3           - 完整扫描 (45个端口)
               -p <ports>  - 自定义端口 (如: -p 80,443,22-25)

示例:
  smartscan 192.168.1.1                    # 标准扫描
  smartscan 192.168.1.0/24 1               # 快速扫描C段
  smartscan 192.168.1.100 3                # 完整扫描
  smartscan 192.168.1.1 -p 70-90          # 自定义端口范围
  smartscan 192.168.1.1 -p 80,443,8080    # 自定义端口列表

端口级别:
  Level 1 (10端口)  : Web + 数据库
  Level 2 (25端口)  : Web + 数据库 + Windows/Linux识别
  Level 3 (45端口)  : 全面扫描所有常见服务
        `,
        args: {
            target: "目标IP或CIDR",
            options: "扫描级别或自定义端口 (可选)"
        },
        code: "../_bin/portscan.x64.o"
    }
});

