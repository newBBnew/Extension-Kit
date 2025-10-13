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
#define BATCH_DELAY 30
#define TIMEOUT_MS 2000

// 端口优先级级别
typedef struct {
    int port;
    const char* service;
    int priority;
} PortInfo;

// Level 1: 快速扫描 (10个高优先级端口)
static PortInfo level1_ports[] = {
    {80, "http", 3}, {443, "https", 3}, {8080, "http-alt", 3}, {8443, "https-alt", 3},
    {1433, "mssql", 3}, {1521, "oracle", 3}, {3306, "mysql", 3}, {5432, "postgresql", 3},
    {6379, "redis", 3}, {27017, "mongodb", 3}
};

// Level 2: 标准扫描 (25个端口 - 包含操作系统识别)
static PortInfo level2_ports[] = {
    // Web
    {80, "http", 3}, {443, "https", 3}, {8080, "http-alt", 3}, {8443, "https-alt", 3},
    // 数据库
    {1433, "mssql", 3}, {1521, "oracle", 3}, {3306, "mysql", 3}, {5432, "postgresql", 3},
    {6379, "redis", 3}, {27017, "mongodb", 3},
    // Windows
    {135, "rpc", 2}, {139, "netbios", 2}, {445, "smb", 3}, {3389, "rdp", 3},
    {5985, "winrm-http", 2}, {5986, "winrm-https", 2},
    // Linux/基础
    {22, "ssh", 3}, {21, "ftp", 2}, {25, "smtp", 2}, {53, "dns", 2},
    {110, "pop3", 2}, {143, "imap", 2}, {993, "imaps", 2}, {995, "pop3s", 2},
    {23, "telnet", 2}
};

// Level 3: 完整扫描 (45个端口)
static PortInfo level3_ports[] = {
    // Web
    {80, "http", 3}, {443, "https", 3}, {8080, "http-alt", 3}, {8443, "https-alt", 3},
    {8000, "http-alt2", 2}, {8888, "http-alt3", 2},
    // 数据库
    {1433, "mssql", 3}, {1521, "oracle", 3}, {3306, "mysql", 3}, {5432, "postgresql", 3},
    {6379, "redis", 3}, {27017, "mongodb", 3}, {9200, "elasticsearch", 2}, {9300, "elasticsearch-tcp", 2},
    // Windows/域控
    {135, "rpc", 2}, {139, "netbios", 2}, {445, "smb", 3}, {3389, "rdp", 3},
    {5985, "winrm-http", 2}, {5986, "winrm-https", 2},
    {88, "kerberos", 2}, {389, "ldap", 2}, {636, "ldaps", 2}, {3268, "gc", 2}, {3269, "gc-ssl", 2},
    // Linux/Unix
    {22, "ssh", 3}, {23, "telnet", 2},
    // 基础设施
    {21, "ftp", 2}, {25, "smtp", 2}, {53, "dns", 2}, {69, "tftp", 1}, {110, "pop3", 2},
    {111, "rpcbind", 2}, {143, "imap", 2}, {993, "imaps", 2}, {995, "pop3s", 2},
    // 其他服务
    {7, "echo", 1}, {9, "discard", 1}, {13, "daytime", 1}, {19, "chargen", 1},
    {37, "time", 1}, {79, "finger", 1}, {113, "ident", 1}, {119, "nntp", 1}
};

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
        MSVCRT$memset(ip_part, 0, sizeof(ip_part));
        for (int i = 0; i < len && i < 31; i++) {
            ip_part[i] = target[i];
        }
        prefix_len = simple_atoi(slash + 1);
    } else {
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
int scan_port(unsigned long ip, int port) {
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
    timeout.tv_sec = TIMEOUT_MS / 1000;
    timeout.tv_usec = (TIMEOUT_MS % 1000) * 1000;
    
    int result = WS2_32$select(0, NULL, &write_fds, NULL, &timeout);
    
    WS2_32$closesocket(sock);
    
    return (result > 0);
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
    char target[64];
    char port_arg[256];
    int level = 2; // 默认标准扫描
    int size;
    char* temp;
    
    BeaconDataParse(&parser, args, len);
    
    // 提取目标
    temp = BeaconDataExtract(&parser, &size);
    if (temp && size > 0 && size < sizeof(target)) {
        MSVCRT$memcpy(target, temp, size);
        target[size] = '\0';
    } else {
        target[0] = '\0';
    }
    
    // 提取选项参数
    if (BeaconDataLength(&parser) > 0) {
        temp = BeaconDataExtract(&parser, &size);
        if (temp && size > 0 && size < sizeof(port_arg)) {
            MSVCRT$memcpy(port_arg, temp, size);
            port_arg[size] = '\0';
        } else {
            port_arg[0] = '\0';
        }
    } else {
        port_arg[0] = '\0';
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting port scan for: %s\n", target);
    
    // 解析目标IP
    unsigned long start_ip, end_ip;
    if (!parse_cidr(target, &start_ip, &end_ip)) {
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
    
    if (port_arg[0] && MSVCRT$strstr(port_arg, "-p")) {
        // 自定义端口模式
        const char* port_spec = MSVCRT$strstr(port_arg, "-p") + 2;
        while (*port_spec == ' ') port_spec++;
        
        port_count = parse_custom_ports(port_spec, ports, MAX_PORTS);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Using custom ports: %s (%d ports)\n", port_spec, port_count);
    } else if (port_arg[0]) {
        // 级别模式
        level = simple_atoi(port_arg);
        
        if (level == 1) {
            port_list = level1_ports;
            list_size = sizeof(level1_ports) / sizeof(PortInfo);
        } else if (level == 3) {
            port_list = level3_ports;
            list_size = sizeof(level3_ports) / sizeof(PortInfo);
        } else {
            level = 2;
            port_list = level2_ports;
            list_size = sizeof(level2_ports) / sizeof(PortInfo);
        }
        
        for (int i = 0; i < list_size && port_count < MAX_PORTS; i++) {
            ports[port_count++] = port_list[i].port;
        }
    } else {
        // 默认标准扫描
        port_list = level2_ports;
        list_size = sizeof(level2_ports) / sizeof(PortInfo);
        
        for (int i = 0; i < list_size && port_count < MAX_PORTS; i++) {
            ports[port_count++] = port_list[i].port;
        }
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Scanning %d ports\n", port_count);
    
    // 开始扫描
    int total_open = 0;
    
    for (unsigned long ip = start_ip; ip <= end_ip; ip++) {
        int host_open = 0;
        
        // 转换IP为点分十进制
        unsigned char* bytes = (unsigned char*)&ip;
        char ip_str[32];
        MSVCRT$sprintf(ip_str, "%d.%d.%d.%d", 
            bytes[3], bytes[2], bytes[1], bytes[0]);
        
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Scanning %s...\n", ip_str);
        
        // 批量扫描端口
        for (int i = 0; i < port_count; i += BATCH_SIZE) {
            int batch_end = (i + BATCH_SIZE > port_count) ? port_count : i + BATCH_SIZE;
            
            for (int j = i; j < batch_end; j++) {
                if (scan_port(ip, ports[j])) {
                    const char* service = "unknown";
                    if (port_arg[0] == '\0' || (port_arg[0] && !MSVCRT$strstr(port_arg, "-p"))) {
                        service = get_service_name(ports[j], port_list, list_size);
                    }
                    BeaconPrintf(CALLBACK_OUTPUT, "  [+] Port %d (%s) - OPEN\n", ports[j], service);
                    host_open++;
                    total_open++;
                }
            }
            
            // 批次间延迟
            if (batch_end < port_count) {
                KERNEL32$Sleep(BATCH_DELAY);
            }
        }
        
        if (host_open > 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Host %s: %d open ports found\n", ip_str, host_open);
        }
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Scan completed. Found %d open ports total.\n", total_open);
}

