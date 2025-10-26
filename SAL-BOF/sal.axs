var metadata = {
    name: "SAL-BOF",
    description: "Situation Awareness Local BOFs"
};

/// HELPERS

// 根据端口特征推测操作系统
function guessOSByPorts(ports) {
    let windows_score = 0;
    let linux_score = 0;
    
    // Windows 特征端口
    if (ports.includes(445))  windows_score += 3;
    if (ports.includes(3389)) windows_score += 3;
    if (ports.includes(135))  windows_score += 2;
    if (ports.includes(139))  windows_score += 1;
    if (ports.includes(5985)) windows_score += 2;
    if (ports.includes(1433)) windows_score += 1;
    
    // Linux 特征端口
    if (ports.includes(22))    linux_score += 2;
    if (ports.includes(3306))  linux_score += 1;
    if (ports.includes(5432))  linux_score += 1;
    if (ports.includes(6379))  linux_score += 1;
    if (ports.includes(27017)) linux_score += 1;
    
    if (windows_score > linux_score) return "windows";
    if (linux_score > windows_score) return "linux";
    return "unknown";
}

// 判断主机是否为有价值的目标
function isValuableTarget(ports) {
    // 只要有开放端口就添加 - 能扫描到说明主机存活且有服务
    return ports.length > 0;
}

// 从扫描结果解析主机信息（支持文本和CSV两种格式）
function parseHostsFromScanOutput(text) {
    let hostsMap = {};
    
    // 文本格式: "  [+] 192.168.1.100:22 (ssh) - OPEN"
    let textRegex = /\[?\+?\]?\s*(\d+\.\d+\.\d+\.\d+):(\d+)\s+\(([^)]+)\)\s+-\s+OPEN/gm;
    let match;
    
    while ((match = textRegex.exec(text)) !== null) {
        let ip = match[1];
        let port = parseInt(match[2]);
        let service = match[3];
        
        if (!hostsMap[ip]) {
            hostsMap[ip] = { address: ip, ports: [], services: [] };
        }
        
        hostsMap[ip].ports.push(port);
        hostsMap[ip].services.push(service);
    }
    
    // CSV 格式: "192.168.1.100,22,ssh,open"
    let csvRegex = /^(\d+\.\d+\.\d+\.\d+),(\d+),([^,]+),open$/gm;
    while ((match = csvRegex.exec(text)) !== null) {
        let ip = match[1];
        let port = parseInt(match[2]);
        let service = match[3];
        
        if (!hostsMap[ip]) {
            hostsMap[ip] = { address: ip, ports: [], services: [] };
        }
        
        hostsMap[ip].ports.push(port);
        hostsMap[ip].services.push(service);
    }
    
    return hostsMap;
}

// 构建目标对象
function buildTargetFromHost(host) {
    let os = guessOSByPorts(host.ports);
    let portList = host.ports.sort((a, b) => a - b).join(', ');
    let serviceList = [...new Set(host.services)].join(', ');
    
    return {
        computer: "",
        domain: "",
        address: host.address,
        os: os,
        os_desk: os.charAt(0).toUpperCase() + os.slice(1),
        tag: "smartscan",
        info: `Ports: ${portList} | Services: ${serviceList}`,
        alive: true
    };
}

/// COMMANDS

var cmd_arp = ax.create_command("arp", "List ARP table", "arp");
cmd_arp.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/arp." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF implementation: arp");
});

var cmd_cacls = ax.create_command("cacls", "List user permissions for the specified file or directory, wildcards supported", "cacls C:\\test.txt");
cmd_cacls.addArgString("path", true);
cmd_cacls.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let path = parsed_json["path"];

    let bof_params = ax.bof_pack("wstr", [path]);
    let bof_path = ax.script_dir() + "_bin/cacls." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "BOF implementation: cacls");
});

var cmd_dir = ax.create_command("dir", "Lists files in a specified directory. Supports wildcards (e.g. \"C:\\Windows\\S*\"). Optionally, it can perform a recursive list with the /s argument", "dir C:\\Users /s");
cmd_dir.addArgString("directory", ".\\");
cmd_dir.addArgBool("/s", "Recursive list");
cmd_dir.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let directory = parsed_json["directory"];
    let recursive = 0;

    if(parsed_json["/s"]) { recursive = 1; }

    let bof_params = ax.bof_pack("wstr,int", [directory, recursive]);
    let bof_path = ax.script_dir() + "_bin/dir." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "BOF implementation: dir");
});

var cmd_env = ax.create_command("env", "List process environment variables", "env");
cmd_env.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/env." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "List process environment variables (BOF)");
});

var cmd_ipconfig = ax.create_command("ipconfig", "List IPv4 address, hostname, and DNS server", "ipconfig");
cmd_ipconfig.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/ipconfig." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF implementation: ipconfig");
});

var cmd_listdns = ax.create_command("listdns", "List DNS cache entries. Attempt to query and resolve each", "listdns");
cmd_listdns.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/listdns." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF implementation: ipconfig /displaydns");
});

var cmd_netstat = ax.create_command("netstat", "Executes the netstat command to display network connections", "netstat");
cmd_netstat.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/netstat." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF implementation: netstat");
});

var cmd_nslookup = ax.create_command("nslookup", "Make a DNS query", "nslookup google.com -s 8.8.8.8 -t A");
cmd_nslookup.addArgString("domain", true);
cmd_nslookup.addArgFlagString("-s", "server", "DNS server is the server you want to query", "");
cmd_nslookup.addArgFlagString("-t", "type", "Record type is something like A, AAAA, or ANY", "A");
cmd_nslookup.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let domain = parsed_json["domain"];
    let server = parsed_json["server"];
    let type   = parsed_json["type"];

    let bof_params = ax.bof_pack("cstr,cstr,cstr", [domain, type, server]);
    let bof_path = ax.script_dir() + "_bin/nslookup." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "BOF implementation: nslookup");
});

var _cmd_privcheck_alwayselevated = ax.create_command("alwayselevated", "Checks if Always Install Elevated is enabled using the registry", "privcheck alwayselevated");
_cmd_privcheck_alwayselevated.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/alwayselevated." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "Task: Checks AlwaysInstallElevated");
});
var _cmd_privcheck_hijackablepath = ax.create_command("hijackablepath", "Checks the path environment variable for writable directories (FILE_ADD_FILE) that can be exploited to elevate privileges", "privcheck hijackablepath");
_cmd_privcheck_hijackablepath.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/hijackablepath." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "Task: Checks HijackablePath");
});
var _cmd_privcheck_tokenpriv = ax.create_command("tokenpriv", "Lists the current token privileges and highlights known vulnerable ones", "privcheck tokenpriv");
_cmd_privcheck_tokenpriv.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/tokenpriv." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "Task: Checks TokenPrivileges");
});
var _cmd_privcheck_unattendfiles = ax.create_command("unattendfiles", "Checks for leftover unattend files that might contain sensitive information", "privcheck unattendfiles");
_cmd_privcheck_unattendfiles.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/unattendfiles." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "Task: Checks UnattendFiles");
});
var _cmd_privcheck_unquotedsvc = ax.create_command("unquotedsvc", "Checks for unquoted service paths", "privcheck unquotedsvc");
_cmd_privcheck_unquotedsvc.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/unquotedsvc." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "Task: Checks Unquoted Service Path");
});
var _cmd_privcheck_vulndrivers = ax.create_command("vulndrivers", "Checks if any service on the system uses a known vulnerable driver (based on loldrivers.io)", "privcheck vulndrivers");
_cmd_privcheck_vulndrivers.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/vulndrivers." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "Task: Checks Vulnerable Drivers");
});
var cmd_findobj = ax.create_command("privcheck", "Perform privcheck functions");
cmd_findobj.addSubCommands([_cmd_privcheck_alwayselevated, _cmd_privcheck_hijackablepath, _cmd_privcheck_tokenpriv, _cmd_privcheck_unattendfiles, _cmd_privcheck_unquotedsvc, _cmd_privcheck_vulndrivers]);

var cmd_routeprint = ax.create_command("routeprint", "List IPv4 routes", "routeprint");
cmd_routeprint.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/routeprint." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF implementation: route");
});

var cmd_uptime = ax.create_command("uptime", "List system boot time and how long it has been running", "uptime");
cmd_uptime.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/uptime." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF implementation: uptime");
});

var cmd_useridletime = ax.create_command("useridletime", "Shows how long the user as been idle, displayed in seconds, minutes, hours and days", "useridletime");
cmd_useridletime.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/useridletime." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF implementation: useridletime");
});

var cmd_whoami = ax.create_command("whoami", "List whoami /all, hours and days", "whoami");
cmd_whoami.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/whoami." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF implementation: whoami /all");
});

var cmd_smartscan = ax.create_command("smartscan", "Smart TCP/UDP port scanner with CIDR and auto-target discovery", "smartscan 192.168.1.1 -l 2");
cmd_smartscan.addArgString("target", true, "Target IP address or CIDR range (e.g. 192.168.1.1 or 10.0.0.0/24)");
cmd_smartscan.addArgFlagString("-l", "level", "Scan level:\n    1 = Fast scan (10 common ports)\n    2 = Standard scan (25 common ports) [default]\n    3 = Full scan (45 common ports)", "2");
cmd_smartscan.addArgFlagString("-p", "ports", "Custom ports: 80,443 or 22-25 or 80,443,8000-9000", "");
cmd_smartscan.addArgFlagString("-e", "exclude", "Exclude ports: 80,443 or 22-25", "");
cmd_smartscan.addArgFlagString("-d", "delay", "Delay between batches in milliseconds (default: 30)", "30");
cmd_smartscan.addArgFlagString("-o", "output", "Output format: txt or csv (default: txt)", "txt");
cmd_smartscan.addArgBool("-u", "Enable UDP scanning (default: TCP)");
cmd_smartscan.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let target  = parsed_json["target"];
    let level   = parsed_json["level"] || "2";
    let ports   = parsed_json["ports"] || "";
    let exclude = parsed_json["exclude"] || "";
    let delay   = parsed_json["delay"] || "30";
    let output  = parsed_json["output"] || "txt";
    let udp     = parsed_json["-u"] ? "1" : "0";
    
    // Hook: 解析扫描结果并自动添加到 Targets（默认行为）
    let hook = function (task) {
        // 解析当前 task 的输出（每个 task 都处理）
        let hostsMap = parseHostsFromScanOutput(task.text);
        let targets = [];
        
        for (let ip in hostsMap) {
            let host = hostsMap[ip];
            if (isValuableTarget(host.ports)) {
                targets.push(buildTargetFromHost(host));
            }
        }
        
        // 立即添加发现的主机
        if (targets.length > 0) {
            ax.targets_add_list(targets);
        }
        
        // 只在最后一个 task 添加提示信息
        if (task.message === "BOF finished" && targets.length > 0) {
            task.text += `\n[*] Auto-added ${targets.length} host(s) to Targets\n`;
        }
        
        // 隐藏中间 task 的 message
        if (task.message !== "BOF finished" && task.index !== 0) {
            task.message = "";
        }
        
        return task;
    };
    
    let params = `${target}|${level}|${ports}|${exclude}|${delay}|${output}|${udp}`;
    let bof_params = ax.bof_pack("cstr", [params]);
    let bof_path = ax.script_dir() + "_bin/portscan." + ax.arch(id) + ".o";
    
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "BOF implementation: smartscan", hook);
});

var group_test = ax.create_commands_group("SAL-BOF", [cmd_arp, cmd_cacls, cmd_dir, cmd_env, cmd_ipconfig, cmd_listdns, cmd_netstat, cmd_nslookup, cmd_findobj, cmd_routeprint, cmd_uptime, cmd_useridletime, cmd_whoami, cmd_smartscan]);
ax.register_commands_group(group_test, ["beacon", "gopher"], ["windows"], []);
