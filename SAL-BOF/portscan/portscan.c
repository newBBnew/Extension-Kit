// SmartPortScan BOF - 智能端口扫描工具
// 支持CIDR、自定义端口、三级扫描策略

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "../_include/beacon.h"

// 动态API声明
DECLSPEC_IMPORT SOCKET WINAPI WS2_32$socket(int, int, int);
DECLSPEC_IMPORT int WINAPI WS2_32$connect(SOCKET, const struct sockaddr*, int);
DECLSPEC_IMPORT int WINAPI WS2_32$closesocket(SOCKET);
DECLSPEC_IMPORT int WINAPI WS2_32$select(int, fd_set*, fd_set*, fd_set*, const struct timeval*);
DECLSPEC_IMPORT u_long WINAPI WS2_32$htonl(u_long);
DECLSPEC_IMPORT u_short WINAPI WS2_32$htons(u_short);
DECLSPEC_IMPORT int WINAPI WS2_32$ioctlsocket(SOCKET, long, u_long*);
DECLSPEC_IMPORT unsigned long WINAPI WS2_32$inet_addr(const char*);
DECLSPEC_IMPORT int WINAPI WS2_32$sendto(SOCKET, const char*, int, int, const struct sockaddr*, int);

WINBASEAPI void* __cdecl MSVCRT$malloc(size_t);
WINBASEAPI void __cdecl MSVCRT$free(void*);
WINBASEAPI int __cdecl MSVCRT$memcmp(const void*, const void*, size_t);
WINBASEAPI void* __cdecl MSVCRT$memset(void*, int, size_t);
WINBASEAPI void* __cdecl MSVCRT$memcpy(void*, const void*, size_t);
WINBASEAPI char* __cdecl MSVCRT$strcpy(char*, const char*);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char*);
WINBASEAPI int __cdecl MSVCRT$strcmp(const char*, const char*);
WINBASEAPI char* __cdecl MSVCRT$strstr(const char*, const char*);
WINBASEAPI int __cdecl MSVCRT$sprintf(char*, const char*, ...);
WINBASEAPI VOID WINAPI KERNEL32$Sleep(DWORD);

// 端口配置
#define MAX_PORTS 100
#define BATCH_SIZE 8
#define DEFAULT_BATCH_DELAY 30
#define DEFAULT_TIMEOUT_MS 2000
#define MAX_PARAM_LEN 512

// 端口优先级级别
typedef struct {
    int port;
    const char* service;
    int priority;
} PortInfo;

// 扫描配置
typedef struct {
    char target[64];
    int level;
    char custom_ports[128];
    char exclude_ports[128];
    int delay_ms;
    int is_udp;
    int is_csv;
} ScanConfig;

// Level 1: 快速扫描 (15个最高优先级端口)
static PortInfo level1_ports[] = {
    // 远程管理 (最关键)
    {22, "ssh", 3}, {3389, "rdp", 3}, {445, "smb", 3},
    // Web 服务
    {80, "http", 3}, {443, "https", 3}, {8080, "http-proxy", 3}, {8443, "https-alt", 3},
    // 数据库 (高价值)
    {3306, "mysql", 3}, {5432, "postgresql", 3}, {1433, "mssql", 3}, {6379, "redis", 3},
    // 现代服务
    {27017, "mongodb", 3}, {9200, "elasticsearch", 3},
    // Windows 关键
    {135, "msrpc", 3}, {5985, "winrm", 3}
};

// Level 2: 标准扫描 (30个端口 - 企业环境全覆盖)
static PortInfo level2_ports[] = {
    // 远程管理
    {22, "ssh", 3}, {23, "telnet", 2}, {3389, "rdp", 3},
    // Web 服务
    {80, "http", 3}, {443, "https", 3}, {8080, "http-proxy", 3}, {8443, "https-alt", 3},
    {3000, "node", 2}, {5000, "flask", 2}, {8000, "http-alt", 2}, {9000, "portainer", 2},
    // 数据库
    {1433, "mssql", 3}, {3306, "mysql", 3}, {5432, "postgresql", 3}, 
    {6379, "redis", 3}, {27017, "mongodb", 3}, {9200, "elasticsearch", 2},
    // Windows
    {135, "msrpc", 3}, {139, "netbios-ssn", 2}, {445, "smb", 3}, 
    {5985, "winrm-http", 2}, {5986, "winrm-https", 2},
    // 容器/云
    {2375, "docker", 2}, {2376, "docker-tls", 2}, {6443, "k8s-api", 2},
    // 基础设施
    {21, "ftp", 2}, {25, "smtp", 2}, {53, "dns", 2}, {3128, "squid", 2}
};

// Level 3: 完整扫描 (50个端口 - 现代企业全栈)
static PortInfo level3_ports[] = {
    // 远程管理
    {22, "ssh", 3}, {23, "telnet", 2}, {3389, "rdp", 3}, {5900, "vnc", 2},
    // Web 服务
    {80, "http", 3}, {443, "https", 3}, {8080, "http-proxy", 3}, {8443, "https-alt", 3},
    {3000, "node", 2}, {4000, "alt-http", 2}, {5000, "flask", 2}, {8000, "http-alt", 2}, 
    {8888, "http-alt2", 2}, {9000, "portainer", 2}, {9090, "prometheus", 2},
    // 数据库
    {1433, "mssql", 3}, {1521, "oracle", 2}, {3306, "mysql", 3}, {5432, "postgresql", 3},
    {6379, "redis", 3}, {11211, "memcached", 2}, {27017, "mongodb", 3}, 
    {9200, "elasticsearch", 2}, {9300, "es-cluster", 2},
    // Windows/域控
    {88, "kerberos", 2}, {135, "msrpc", 3}, {139, "netbios-ssn", 2}, {445, "smb", 3},
    {389, "ldap", 2}, {636, "ldaps", 2}, {3268, "gc", 2}, {3269, "gc-ssl", 2},
    {5985, "winrm-http", 2}, {5986, "winrm-https", 2},
    // 容器/云原生
    {2375, "docker", 2}, {2376, "docker-tls", 2}, {2377, "docker-swarm", 1},
    {6443, "k8s-api", 2}, {10250, "kubelet", 2},
    // DevOps 工具
    {8081, "nexus", 2}, {8082, "artifactory", 2}, {8200, "vault", 2},
    {9091, "prometheus-push", 1}, {3001, "grafana", 2}, {50000, "jenkins", 2},
    // 基础设施
    {21, "ftp", 2}, {25, "smtp", 2}, {53, "dns", 2}, {69, "tftp", 1},
    {111, "rpcbind", 2}, {161, "snmp", 2}, {3128, "squid", 2}
};

// 前向声明
int simple_atoi(const char* str);
int parse_custom_ports(const char* port_str, int* ports, int max_ports);

// 字符串分割函数（简化版，用于解析参数）
char* simple_strtok(char* str, char delim, char** saveptr) {
    char* start;
    if (str) {
        start = str;
    } else {
        start = *saveptr;
        if (!start) return NULL;
    }
    
    // 跳过前导分隔符
    while (*start == delim) start++;
    if (*start == '\0') return NULL;
    
    // 查找下一个分隔符
    char* end = start;
    while (*end && *end != delim) end++;
    
    if (*end) {
        *end = '\0';
        *saveptr = end + 1;
    } else {
        *saveptr = NULL;
    }
    
    return start;
}

// 解析参数字符串：target|level|ports|exclude|delay|output|udp
int parse_params(char* param_str, ScanConfig* config) {
    char* saveptr = NULL;
    char* token;
    int field = 0;
    
    // 初始化默认值
    config->level = 2;
    config->custom_ports[0] = '\0';
    config->exclude_ports[0] = '\0';
    config->delay_ms = DEFAULT_BATCH_DELAY;
    config->is_udp = 0;
    config->is_csv = 0;
    
    token = simple_strtok(param_str, '|', &saveptr);
    while (token && field < 7) {
        switch (field) {
            case 0: // target
                MSVCRT$strcpy(config->target, token);
                break;
            case 1: // level
                if (token[0] >= '1' && token[0] <= '3') {
                    config->level = token[0] - '0';
                }
                break;
            case 2: // custom_ports
                if (token[0]) {
                    MSVCRT$strcpy(config->custom_ports, token);
                }
                break;
            case 3: // exclude_ports
                if (token[0]) {
                    MSVCRT$strcpy(config->exclude_ports, token);
                }
                break;
            case 4: // delay
                config->delay_ms = simple_atoi(token);
                if (config->delay_ms < 0) config->delay_ms = DEFAULT_BATCH_DELAY;
                break;
            case 5: // output format
                if (token[0] == 'c' || token[0] == 'C') { // csv
                    config->is_csv = 1;
                }
                break;
            case 6: // udp flag
                if (token[0] == '1') {
                    config->is_udp = 1;
                }
                break;
        }
        field++;
        token = simple_strtok(NULL, '|', &saveptr);
    }
    
    return (field > 0); // 至少解析到 target
}

// 解析IP地址为32位整数
unsigned long parse_ip(const char* ip_str) {
    return WS2_32$inet_addr(ip_str);
}

// 简单的字符串转整数
int simple_atoi(const char* str) {
    int result = 0;
    int sign = 1;
    
    if (*str == '-') {
        sign = -1;
        str++;
    }
    
    while (*str >= '0' && *str <= '9') {
        result = result * 10 + (*str - '0');
        str++;
    }
    
    return result * sign;
}

// 解析CIDR (例如: 192.168.1.0/24)
int parse_cidr(const char* target, unsigned long* start_ip, unsigned long* end_ip) {
    char ip_part[32];
    int prefix_len = 32;
    const char* slash = MSVCRT$strstr(target, "/");
    
    if (slash) {
        int len = slash - target;
        if (len >= sizeof(ip_part)) len = sizeof(ip_part) - 1;
        MSVCRT$memset(ip_part, 0, sizeof(ip_part));
        for (int i = 0; i < len; i++) {
            ip_part[i] = target[i];
        }
        prefix_len = simple_atoi(slash + 1);
        if (prefix_len < 0 || prefix_len > 32) {
            prefix_len = 32; // 无效前缀长度，使用单个IP
        }
    } else {
        int len = MSVCRT$strlen(target);
        if (len >= sizeof(ip_part)) return 0; // IP地址字符串太长
        MSVCRT$strcpy(ip_part, target);
    }
    
    *start_ip = parse_ip(ip_part);
    if (*start_ip == INADDR_NONE) return 0;
    
    *start_ip = WS2_32$htonl(*start_ip);
    
    if (prefix_len >= 32) {
        *end_ip = *start_ip;
    } else {
        unsigned long mask = (0xFFFFFFFF << (32 - prefix_len));
        *start_ip = *start_ip & mask;
        *end_ip = *start_ip | (~mask);
    }
    
    return 1;
}

// 解析自定义端口 (例如: "80,443,22-25")
int parse_custom_ports(const char* port_str, int* ports, int max_ports) {
    char buffer[256];
    int count = 0;
    int i = 0, j = 0;
    
    MSVCRT$memset(buffer, 0, sizeof(buffer));
    
    while (port_str[i] && count < max_ports) {
        // 跳过空格
        while (port_str[i] == ' ') i++;
        
        // 读取数字或范围
        j = 0;
        while (port_str[i] && port_str[i] != ',' && j < 63) {
            buffer[j++] = port_str[i++];
        }
        buffer[j] = '\0';
        
        // 检查是否是范围 (例如: 22-25)
        char* dash = MSVCRT$strstr(buffer, "-");
        if (dash) {
            *dash = '\0';
            int start_port = simple_atoi(buffer);
            int end_port = simple_atoi(dash + 1);
            
            for (int p = start_port; p <= end_port && count < max_ports; p++) {
                if (p >= 1 && p <= 65535) {
                    ports[count++] = p;
                }
            }
        } else if (j > 0) {
            int port = simple_atoi(buffer);
            if (port >= 1 && port <= 65535) {
                ports[count++] = port;
            }
        }
        
        if (port_str[i] == ',') i++;
    }
    
    return count;
}

// TCP端口扫描
int scan_tcp_port(unsigned long ip, int port, int timeout_ms) {
    SOCKET sock = WS2_32$socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return 0;
    
    // 设置非阻塞模式
    u_long mode = 1;
    WS2_32$ioctlsocket(sock, FIONBIO, &mode);
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = WS2_32$htonl(ip);
    addr.sin_port = WS2_32$htons(port);
    
    // 尝试连接
    WS2_32$connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    
    // 使用select检查连接状态
    fd_set write_fds;
    FD_ZERO(&write_fds);
    FD_SET(sock, &write_fds);
    
    struct timeval timeout;
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    
    int result = WS2_32$select(0, NULL, &write_fds, NULL, &timeout);
    
    WS2_32$closesocket(sock);
    
    return (result > 0);
}

// UDP端口扫描（轻量级实现）
int scan_udp_port(unsigned long ip, int port, int timeout_ms) {
    SOCKET sock = WS2_32$socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return 0;
    
    // 设置非阻塞模式
    u_long mode = 1;
    WS2_32$ioctlsocket(sock, FIONBIO, &mode);
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = WS2_32$htonl(ip);
    addr.sin_port = WS2_32$htons(port);
    
    // 发送空 UDP 包
    char probe[1] = {0};
    WS2_32$sendto(sock, probe, sizeof(probe), 0, (struct sockaddr*)&addr, sizeof(addr));
    
    // 使用select等待响应
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);
    
    struct timeval timeout;
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    
    int result = WS2_32$select(0, &read_fds, NULL, NULL, &timeout);
    
    WS2_32$closesocket(sock);
    
    // UDP 扫描：有响应=开放，无响应=可能开放/过滤
    // 这里我们假设无响应=开放（简化实现）
    return (result >= 0); // 返回1表示端口可能开放
}

// 检查端口是否在排除列表中
int is_port_excluded(int port, int* exclude_list, int exclude_count) {
    for (int i = 0; i < exclude_count; i++) {
        if (exclude_list[i] == port) {
            return 1;
        }
    }
    return 0;
}

// 获取服务名称
const char* get_service_name(int port, PortInfo* port_list, int list_size) {
    for (int i = 0; i < list_size; i++) {
        if (port_list[i].port == port) {
            return port_list[i].service;
        }
    }
    return "unknown";
}

// 主扫描函数
void go(char* args, int len) {
    datap parser;
    ScanConfig config;
    char param_str[MAX_PARAM_LEN];
    int size;
    char* temp;
    
    BeaconDataParse(&parser, args, len);
    
    // 提取参数字符串 (格式: target|level|ports|exclude|delay|output|udp)
    temp = BeaconDataExtract(&parser, &size);
    if (temp && size > 0 && size < sizeof(param_str)) {
        MSVCRT$memcpy(param_str, temp, size);
        param_str[size] = '\0';
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] Invalid parameters\n");
        return;
    }
    
    // 解析参数
    if (!parse_params(param_str, &config)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to parse parameters\n");
        return;
    }
    
    // 打印扫描配置
    const char* scan_type = config.is_udp ? "UDP" : "TCP";
    const char* output_fmt = config.is_csv ? "CSV" : "TXT";
    BeaconPrintf(CALLBACK_OUTPUT, "[*] SmartScan - %s Port Scanner\n", scan_type);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Target: %s\n", config.target);
    
    // 解析目标IP
    unsigned long start_ip, end_ip;
    if (!parse_cidr(config.target, &start_ip, &end_ip)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Invalid target format\n");
        return;
    }
    
    unsigned long total_hosts = end_ip - start_ip + 1;
    if (total_hosts > 1) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] CIDR expanded to %lu IP addresses\n", total_hosts);
    }
    
    // 确定扫描端口
    int ports[MAX_PORTS];
    int port_count = 0;
    PortInfo* port_list;
    int list_size;
    
    // 判断是预定义级别还是自定义端口
    if (config.custom_ports[0]) {
        // 自定义端口模式
        port_count = parse_custom_ports(config.custom_ports, ports, MAX_PORTS);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Custom ports: %s (%d ports)\n", config.custom_ports, port_count);
        port_list = NULL;
        list_size = 0;
    } else {
        // 级别模式
        if (config.level == 1) {
            port_list = level1_ports;
            list_size = sizeof(level1_ports) / sizeof(PortInfo);
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Fast scan (level 1): %d ports\n", list_size);
        } else if (config.level == 3) {
            port_list = level3_ports;
            list_size = sizeof(level3_ports) / sizeof(PortInfo);
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Full scan (level 3): %d ports\n", list_size);
        } else {
            port_list = level2_ports;
            list_size = sizeof(level2_ports) / sizeof(PortInfo);
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Standard scan (level 2): %d ports\n", list_size);
        }
        
        for (int i = 0; i < list_size && port_count < MAX_PORTS; i++) {
            ports[port_count++] = port_list[i].port;
        }
    }
    
    // 处理排除端口
    int exclude_ports[MAX_PORTS];
    int exclude_count = 0;
    if (config.exclude_ports[0]) {
        exclude_count = parse_custom_ports(config.exclude_ports, exclude_ports, MAX_PORTS);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Excluding %d ports\n", exclude_count);
        
        // 从扫描列表中移除排除的端口
        int filtered_count = 0;
        for (int i = 0; i < port_count; i++) {
            if (!is_port_excluded(ports[i], exclude_ports, exclude_count)) {
                ports[filtered_count++] = ports[i];
            }
        }
        port_count = filtered_count;
    }
    
    if (port_count == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] No valid ports to scan\n");
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Delay: %dms | Output: %s\n", config.delay_ms, output_fmt);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Scanning %d ports...\n", port_count);
    
    // CSV 头部
    if (config.is_csv) {
        BeaconPrintf(CALLBACK_OUTPUT, "IP,Port,Service,Status\n");
    }
    
    // 开始扫描
    int total_open = 0;
    int timeout_ms = DEFAULT_TIMEOUT_MS;
    
    for (unsigned long ip = start_ip; ip <= end_ip; ip++) {
        int host_open = 0;
        
        // 转换IP为点分十进制
        unsigned char* bytes = (unsigned char*)&ip;
        char ip_str[32];
        MSVCRT$sprintf(ip_str, "%d.%d.%d.%d", 
            bytes[3], bytes[2], bytes[1], bytes[0]);
        
        if (!config.is_csv) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Scanning %s...\n", ip_str);
        }
        
        // 批量扫描端口
        for (int i = 0; i < port_count; i++) {
            int is_open;
            
            if (config.is_udp) {
                is_open = scan_udp_port(ip, ports[i], timeout_ms);
            } else {
                is_open = scan_tcp_port(ip, ports[i], timeout_ms);
            }
            
            if (is_open) {
                const char* service = "unknown";
                if (port_list && list_size > 0) {
                    service = get_service_name(ports[i], port_list, list_size);
                }
                
                if (config.is_csv) {
                    BeaconPrintf(CALLBACK_OUTPUT, "%s,%d,%s,open\n", 
                        ip_str, ports[i], service);
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT, "  [+] %s:%d (%s) - OPEN\n", 
                        ip_str, ports[i], service);
                }
                
                host_open++;
                total_open++;
            }
            
            // 批量延迟控制
            if ((i + 1) % BATCH_SIZE == 0 && config.delay_ms > 0) {
                KERNEL32$Sleep(config.delay_ms);
            }
        }
        
        if (!config.is_csv && host_open == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "  [-] No open ports found\n");
        }
    }
    
    // 扫描完成总结
    if (!config.is_csv) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Scan complete: %d open ports found\n", total_open);
    }
}

