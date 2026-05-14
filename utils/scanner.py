# -*- coding: utf-8 -*-
"""
端口扫描模块
使用 python-nmap 库封装 Nmap 扫描逻辑

注意：使用本模块需要在宿主机上安装 nmap 工具
- Windows: 从 https://nmap.org/download.html 下载安装
- Linux: sudo apt-get install nmap 或 sudo yum install nmap
- macOS: brew install nmap
"""

import json
import re
import socket
import os
import subprocess
import nmap
from datetime import datetime


def find_nmap_path():
    """
    在 Windows 系统上查找 nmap 可执行文件路径

    Returns:
        str: nmap 路径，如果找不到返回 None
    """
    # 常见的 nmap 安装路径
    common_paths = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        r"D:\Program Files (x86)\Nmap\nmap.exe",
        r"D:\Program Files\Nmap\nmap.exe",
        r"E:\Program Files (x86)\Nmap\nmap.exe",
        r"E:\Program Files\Nmap\nmap.exe",
    ]

    # 检查常见路径
    for path in common_paths:
        if os.path.isfile(path):
            return path

    # 尝试使用 where 命令查找
    try:
        result = subprocess.run(
            ['where', 'nmap'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            path = result.stdout.strip().split('\n')[0]
            if os.path.isfile(path):
                return path
    except:
        pass

    return None


def parse_version(version_str):
    """
    解析版本字符串为可比较的元组

    Args:
        version_str: 版本字符串，如 "2.4.49", "8.0.25", "7.7p1"

    Returns:
        tuple: 版本号元组，如 (2, 4, 49)
    """
    if not version_str:
        return (0,)

    # 移除常见的版本前缀和后缀
    version_str = re.sub(r'^[vV]', '', version_str)
    version_str = re.sub(r'[a-zA-Z].*$', '', version_str)

    # 提取数字部分
    parts = re.findall(r'\d+', version_str)
    if not parts:
        return (0,)

    return tuple(int(p) for p in parts)


def compare_versions(version1, version2):
    """
    比较两个版本号

    Args:
        version1: 第一个版本字符串
        version2: 第二个版本字符串

    Returns:
        int: -1 (version1 < version2), 0 (相等), 1 (version1 > version2)
    """
    v1 = parse_version(version1)
    v2 = parse_version(version2)

    # 补齐长度
    max_len = max(len(v1), len(v2))
    v1 = v1 + (0,) * (max_len - len(v1))
    v2 = v2 + (0,) * (max_len - len(v2))

    for a, b in zip(v1, v2):
        if a < b:
            return -1
        elif a > b:
            return 1
    return 0


def is_version_vulnerable(current_version, max_safe_version):
    """
    检查当前版本是否存在漏洞（低于安全版本）

    Args:
        current_version: 当前版本
        max_safe_version: 最高安全版本

    Returns:
        bool: 是否存在漏洞
    """
    if not current_version:
        return False  # 无版本信息时不报告漏洞
    return compare_versions(current_version, max_safe_version) <= 0


def validate_target(target):
    """
    验证目标地址是否合法

    Args:
        target: 目标IP、域名或完整URL

    Returns:
        tuple: (是否合法, 错误信息)
    """
    if not target or not target.strip():
        return False, "目标地址不能为空"

    target = target.strip()

    # 检查是否包含危险字符（防止命令注入）
    dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '[', ']', '<', '>', '\n', '\r']
    for char in dangerous_chars:
        if char in target:
            return False, f"目标地址包含非法字符: {char}"

    # 尝试解析完整 URL（支持 http:// 和 https://）
    try:
        parsed = urllib.parse.urlparse(target)
        if parsed.scheme in ('http', 'https') and parsed.hostname:
            # 使用 hostname 作为实际扫描目标
            target = parsed.hostname
        elif parsed.scheme == '' and parsed.path:
            # 如果没有 scheme，可能是直接输入的域名或IP
            pass
    except:
        pass

    # IP 地址格式验证（支持带端口的格式，如 192.168.1.1:8080）
    ip_with_port_pattern = r'^(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?$'
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(-\d{1,3})?$'
    
    if re.match(ip_with_port_pattern, target):
        # 提取 IP 部分进行验证
        ip_part = target.split(':')[0]
        parts = ip_part.split('.')
        for part in parts:
            if int(part) > 255:
                return False, f"IP 地址格式错误: {target}"
        return True, None
    
    if re.match(ip_pattern, target):
        # 验证 IP 地址各段是否在 0-255 范围内
        parts = target.split('-')[0].split('.')
        for part in parts:
            if int(part) > 255:
                return False, f"IP 地址格式错误: {target}"
        return True, None

    # CIDR 格式验证
    cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    if re.match(cidr_pattern, target):
        ip_part, cidr = target.split('/')
        parts = ip_part.split('.')
        for part in parts:
            if int(part) > 255:
                return False, f"CIDR 格式错误: {target}"
        if int(cidr) > 32:
            return False, f"CIDR 格式错误: {target}"
        return True, None

    # 域名格式验证（支持带端口的格式，如 example.com:8080）
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*(:\d{1,5})?$'
    if re.match(domain_pattern, target):
        # 提取主机名部分进行解析
        host_part = target.split(':')[0]
        # 尝试解析域名
        try:
            socket.gethostbyname(host_part)
            return True, None
        except socket.gaierror:
            return False, f"无法解析域名: {host_part}"

    return False, f"无效的目标地址格式: {target}"


# 已知漏洞版本规则（硬编码模拟）
VULNERABLE_VERSIONS = {
    'ssh': {
        'OpenSSH': {
            'max_safe_version': '8.0',
            'vulnerabilities': [
                {
                    'name': 'OpenSSH 用户枚举漏洞',
                    'cve': 'CVE-2018-15473',
                    'risk': 'mid',
                    'description': 'OpenSSH 7.7及以下版本存在用户枚举漏洞，攻击者可以判断系统中是否存在特定用户。',
                    'solution': '升级 OpenSSH 到 7.8 或更高版本。'
                }
            ]
        }
    },
    'http': {
        'Apache': {
            'max_safe_version': '2.4.49',
            'vulnerabilities': [
                {
                    'name': 'Apache HTTP Server 路径遍历漏洞',
                    'cve': 'CVE-2021-41773',
                    'risk': 'high',
                    'description': 'Apache HTTP Server 2.4.49 版本存在路径遍历漏洞，攻击者可能读取服务器上的任意文件。',
                    'solution': '升级到 Apache HTTP Server 2.4.50 或更高版本。'
                }
            ]
        },
        'nginx': {
            'max_safe_version': '1.20.0',
            'vulnerabilities': [
                {
                    'name': 'Nginx 缓冲区溢出漏洞',
                    'cve': 'CVE-2021-23017',
                    'risk': 'high',
                    'description': 'Nginx 1.20.0 之前版本的 DNS 解析器存在缓冲区溢出漏洞。',
                    'solution': '升级到 Nginx 1.20.1 或更高版本。'
                }
            ]
        }
    },
    'ftp': {
        'vsftpd': {
            'max_safe_version': '3.0.3',
            'vulnerabilities': [
                {
                    'name': 'vsftpd 后门漏洞',
                    'cve': 'CVE-2011-2523',
                    'risk': 'high',
                    'description': 'vsftpd 2.3.4 版本存在后门漏洞，攻击者可获取 root shell。',
                    'solution': '升级到 vsftpd 2.3.5 或更高版本，并验证软件来源。'
                }
            ]
        }
    },
    'mysql': {
        'MySQL': {
            'max_safe_version': '8.0.25',
            'vulnerabilities': [
                {
                    'name': 'MySQL 权限提升漏洞',
                    'cve': 'CVE-2021-2307',
                    'risk': 'mid',
                    'description': 'MySQL 8.0.25 之前版本存在权限提升漏洞。',
                    'solution': '升级到 MySQL 8.0.26 或更高版本。'
                }
            ]
        }
    },
    'smtp': {
        'Postfix': {
            'max_safe_version': '3.5.0',
            'vulnerabilities': [
                {
                    'name': 'Postfix SMTP 走私漏洞',
                    'cve': 'CVE-2023-51764',
                    'risk': 'mid',
                    'description': 'Postfix 某些版本存在 SMTP 走私漏洞，可能导致邮件欺骗。',
                    'solution': '升级 Postfix 并配置严格的 SMTP 协议检查。'
                }
            ]
        }
    },
    'rdp': {
        'Microsoft': {
            'max_safe_version': '10.0',
            'vulnerabilities': [
                {
                    'name': 'BlueKeep 远程代码执行漏洞',
                    'cve': 'CVE-2019-0708',
                    'risk': 'high',
                    'description': 'Windows RDP 服务存在严重的远程代码执行漏洞，可被蠕虫利用。',
                    'solution': '安装微软安全更新，禁用不必要的 RDP 服务，启用网络级别身份验证(NLA)。'
                },
                {
                    'name': 'RDPElevation 权限提升漏洞',
                    'cve': 'CVE-2021-34527',
                    'risk': 'high',
                    'description': 'Windows Print Spooler 服务存在权限提升漏洞，可导致本地用户获得 SYSTEM 权限。',
                    'solution': '安装微软安全更新，禁用 Print Spooler 服务（如不需要）。'
                }
            ]
        }
    },
    'telnet': {
        'default': {
            'max_safe_version': '0',
            'vulnerabilities': [
                {
                    'name': 'Telnet 明文传输风险',
                    'cve': 'N/A',
                    'risk': 'high',
                    'description': 'Telnet 协议以明文方式传输数据，包括用户名和密码，容易被窃听。',
                    'solution': '禁用 Telnet 服务，改用 SSH 进行远程管理。'
                }
            ]
        }
    },
    'smb': {
        'Microsoft': {
            'max_safe_version': '10.0.14393',
            'vulnerabilities': [
                {
                    'name': '永恒之蓝 远程代码执行漏洞',
                    'cve': 'CVE-2017-0144',
                    'risk': 'high',
                    'description': 'Windows SMBv1 协议存在远程代码执行漏洞，攻击者可利用此漏洞在目标系统上执行任意代码，无需认证。此漏洞被 WannaCry 勒索软件广泛利用。',
                    'solution': '安装微软安全更新 MS17-010，禁用 SMBv1 协议，限制 445 端口访问。'
                },
                {
                    'name': 'Petya/NotPetya 漏洞',
                    'cve': 'CVE-2017-0145',
                    'risk': 'high',
                    'description': '与永恒之蓝相关的 SMB 漏洞，被 Petya 勒索软件利用进行大规模攻击。',
                    'solution': '安装微软安全更新 MS17-010，禁用 SMBv1 协议。'
                },
                {
                    'name': 'SMB Relay 攻击漏洞',
                    'cve': 'CVE-2019-1040',
                    'risk': 'high',
                    'description': 'SMB 协议存在中继攻击漏洞，攻击者可利用此漏洞进行凭据窃取和权限提升。',
                    'solution': '启用 SMB 签名，禁用 NTLMv1，使用 Kerberos 认证。'
                }
            ]
        }
    },
    'mssql': {
        'Microsoft SQL Server': {
            'max_safe_version': '15.0',
            'vulnerabilities': [
                {
                    'name': 'SQL Server 远程代码执行漏洞',
                    'cve': 'CVE-2021-1675',
                    'risk': 'high',
                    'description': 'Windows Print Spooler 服务漏洞影响 SQL Server，可导致远程代码执行。',
                    'solution': '安装微软安全更新，限制 SQL Server 服务账户权限。'
                }
            ]
        }
    },
    'redis': {
        'Redis': {
            'max_safe_version': '6.0.0',
            'vulnerabilities': [
                {
                    'name': 'Redis 未授权访问漏洞',
                    'cve': 'CVE-2015-4332',
                    'risk': 'high',
                    'description': 'Redis 默认配置存在未授权访问漏洞，攻击者可直接访问数据库并执行任意命令。',
                    'solution': '绑定到本地回环地址，设置密码认证，禁止外网访问。'
                },
                {
                    'name': 'Redis Lua 沙箱逃逸漏洞',
                    'cve': 'CVE-2022-0543',
                    'risk': 'high',
                    'description': 'Redis Lua 脚本引擎存在沙箱逃逸漏洞，攻击者可执行任意系统命令。',
                    'solution': '升级 Redis 到 7.0.0 或更高版本，禁用不必要的 Lua 脚本执行。'
                }
            ]
        }
    },
    'mongodb': {
        'MongoDB': {
            'max_safe_version': '5.0.0',
            'vulnerabilities': [
                {
                    'name': 'MongoDB 未授权访问漏洞',
                    'cve': 'CVE-2017-1000128',
                    'risk': 'high',
                    'description': 'MongoDB 默认配置存在未授权访问漏洞，攻击者可直接访问数据库。',
                    'solution': '启用认证，绑定到本地地址，禁止外网访问。'
                }
            ]
        }
    },
    'vnc': {
        'VNC': {
            'max_safe_version': '4.0',
            'vulnerabilities': [
                {
                    'name': 'VNC 认证绕过漏洞',
                    'cve': 'CVE-2018-7863',
                    'risk': 'high',
                    'description': 'RealVNC 存在认证绕过漏洞，攻击者可绕过密码验证获得远程访问权限。',
                    'solution': '升级 VNC 到最新版本，使用加密连接，限制访问IP。'
                }
            ]
        }
    },
    'netbios': {
        'default': {
            'max_safe_version': '0',
            'vulnerabilities': [
                {
                    'name': 'NetBIOS 信息泄露漏洞',
                    'cve': 'N/A',
                    'risk': 'mid',
                    'description': 'NetBIOS 服务可能泄露系统信息，包括主机名、用户名等敏感信息。',
                    'solution': '禁用不必要的 NetBIOS 服务，限制 139 端口访问。'
                }
            ]
        }
    },
    'msrpc': {
        'Microsoft': {
            'max_safe_version': '0',
            'vulnerabilities': [
                {
                    'name': 'MSRPC 远程代码执行漏洞',
                    'cve': 'CVE-2020-0668',
                    'risk': 'high',
                    'description': 'Windows RPC 服务存在远程代码执行漏洞，攻击者可利用此漏洞获得系统控制权。',
                    'solution': '安装微软安全更新，限制 135 端口访问。'
                }
            ]
        }
    }
}

# 高风险端口列表
HIGH_RISK_PORTS = {
    21: {'service': 'FTP', 'risk': 'mid', 'description': 'FTP服务可能存在匿名登录或弱密码风险'},
    22: {'service': 'SSH', 'risk': 'low', 'description': 'SSH服务，建议使用密钥认证并禁用root登录'},
    23: {'service': 'Telnet', 'risk': 'high', 'description': 'Telnet使用明文传输，强烈建议禁用'},
    25: {'service': 'SMTP', 'risk': 'mid', 'description': 'SMTP服务可能被利用发送垃圾邮件'},
    53: {'service': 'DNS', 'risk': 'mid', 'description': 'DNS服务可能遭受放大攻击'},
    110: {'service': 'POP3', 'risk': 'mid', 'description': 'POP3明文协议，建议使用POP3S'},
    135: {'service': 'MSRPC', 'risk': 'high', 'description': 'Windows RPC服务，常被恶意软件利用'},
    139: {'service': 'NetBIOS', 'risk': 'high', 'description': 'NetBIOS服务可能泄露系统信息'},
    143: {'service': 'IMAP', 'risk': 'mid', 'description': 'IMAP明文协议，建议使用IMAPS'},
    445: {'service': 'SMB', 'risk': 'high', 'description': 'SMB服务是勒索软件的常见攻击目标'},
    1433: {'service': 'MSSQL', 'risk': 'high', 'description': 'SQL Server数据库，需要强密码保护'},
    1521: {'service': 'Oracle', 'risk': 'high', 'description': 'Oracle数据库，需要严格的访问控制'},
    3306: {'service': 'MySQL', 'risk': 'high', 'description': 'MySQL数据库不应暴露在公网'},
    3389: {'service': 'RDP', 'risk': 'high', 'description': 'Windows远程桌面，存在多个严重漏洞'},
    5432: {'service': 'PostgreSQL', 'risk': 'high', 'description': 'PostgreSQL数据库不应暴露在公网'},
    5900: {'service': 'VNC', 'risk': 'high', 'description': 'VNC远程桌面可能存在弱密码'},
    6379: {'service': 'Redis', 'risk': 'high', 'description': 'Redis未授权访问是常见漏洞'},
    8080: {'service': 'HTTP-Proxy', 'risk': 'mid', 'description': '常见的代理/管理端口'},
    27017: {'service': 'MongoDB', 'risk': 'high', 'description': 'MongoDB未授权访问是常见漏洞'},
}


class PortScanner:
    """
    端口扫描器类
    封装 nmap 扫描功能，支持 TCP/UDP 扫描
    """

    def __init__(self):
        """初始化扫描器"""
        # Windows 下先尝试查找并添加 nmap 到 PATH
        nmap_path = find_nmap_path()
        if nmap_path:
            nmap_dir = os.path.dirname(nmap_path)
            current_path = os.environ.get('PATH', '')
            if nmap_dir not in current_path:
                os.environ['PATH'] = nmap_dir + os.pathsep + current_path

        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError as e:
            if nmap_path:
                raise Exception(
                    f"找到 nmap ({nmap_path})，但初始化失败。\n"
                    f"请尝试将 '{os.path.dirname(nmap_path)}' 手动添加到系统 PATH 环境变量，然后重启。"
                )
            else:
                raise Exception(
                    "未找到 nmap 程序。请确保：\n"
                    "1. 已从 https://nmap.org/download.html 下载并安装 Nmap\n"
                    "2. 将 Nmap 安装目录添加到系统 PATH 环境变量\n"
                    "3. 重启命令行或 IDE 后重试"
                )

    def scan(self, target, ports='1-1000', protocol='tcp', arguments='-sV'):
        """
        执行端口扫描

        Args:
            target: 目标IP或域名
            ports: 端口范围，如 '22,80,443' 或 '1-1000'
            protocol: 协议类型 'tcp' 或 'udp'
            arguments: nmap 额外参数

        Returns:
            dict: 扫描结果
        """
        try:
            # 根据协议选择扫描参数
            if protocol == 'udp':
                scan_args = f'-sU {arguments}'
            else:
                scan_args = f'-sT {arguments}'

            # 执行扫描
            self.nm.scan(hosts=target, ports=ports, arguments=scan_args)

            # 解析结果
            result = self._parse_results(target)
            return result

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'target': target,
                'scan_time': datetime.now().isoformat()
            }

    def _parse_results(self, target):
        """
        解析 nmap 扫描结果

        Args:
            target: 扫描目标

        Returns:
            dict: 解析后的结果
        """
        result = {
            'success': True,
            'target': target,
            'scan_time': datetime.now().isoformat(),
            'hosts': [],
            'open_ports': [],
            'vulnerabilities': []
        }

        for host in self.nm.all_hosts():
            host_info = {
                'ip': host,
                'hostname': self.nm[host].hostname() if self.nm[host].hostname() else host,
                'state': self.nm[host].state(),
                'ports': []
            }

            # 遍历所有协议
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()

                for port in sorted(ports):
                    port_info = self.nm[host][proto][port]
                    port_data = {
                        'port': port,
                        'protocol': proto,
                        'state': port_info['state'],
                        'service': port_info.get('name', 'unknown'),
                        'version': port_info.get('version', ''),
                        'product': port_info.get('product', ''),
                        'extrainfo': port_info.get('extrainfo', '')
                    }

                    if port_info['state'] == 'open':
                        host_info['ports'].append(port_data)
                        result['open_ports'].append(port_data)

                        # 检测漏洞
                        vulns = self._check_vulnerabilities(port_data)
                        result['vulnerabilities'].extend(vulns)

            result['hosts'].append(host_info)

        # 去重漏洞
        seen = set()
        unique_vulns = []
        for v in result['vulnerabilities']:
            key = (v['name'], v['port'])
            if key not in seen:
                seen.add(key)
                unique_vulns.append(v)
        result['vulnerabilities'] = unique_vulns

        return result

    def _check_vulnerabilities(self, port_data):
        """
        检测端口相关的漏洞

        Args:
            port_data: 端口信息

        Returns:
            list: 检测到的漏洞列表
        """
        vulnerabilities = []
        port = port_data['port']
        service = port_data['service'].lower()
        product = port_data.get('product', '')
        version = port_data.get('version', '')

        # 1. 检查高风险端口
        if port in HIGH_RISK_PORTS:
            risk_info = HIGH_RISK_PORTS[port]
            vulnerabilities.append({
                'name': f'{risk_info["service"]} 端口开放风险',
                'port': port,
                'service': service,
                'risk': risk_info['risk'],
                'description': risk_info['description'],
                'solution': f'评估是否需要开放端口 {port}，如非必要请关闭或限制访问IP范围。',
                'cve': 'N/A'
            })

        # 2. 检查服务版本漏洞
        if service in VULNERABLE_VERSIONS:
            for sw_name, sw_info in VULNERABLE_VERSIONS[service].items():
                if sw_name.lower() in product.lower() or sw_name == 'default':
                    # 使用版本比较逻辑判断是否存在漏洞
                    max_safe = sw_info.get('max_safe_version', '0')
                    if sw_name == 'default' or is_version_vulnerable(version, max_safe):
                        for vuln in sw_info['vulnerabilities']:
                            vulnerabilities.append({
                                'name': vuln['name'],
                                'port': port,
                                'service': f'{product} {version}' if product else service,
                                'risk': vuln['risk'],
                                'description': vuln['description'],
                                'solution': vuln['solution'],
                                'cve': vuln['cve']
                            })

        # 3. Telnet 特殊处理（总是高危）
        if service == 'telnet' and not any(v['service'] == 'telnet' for v in vulnerabilities):
            vulnerabilities.append({
                'name': 'Telnet 明文传输风险',
                'port': port,
                'service': 'telnet',
                'risk': 'high',
                'description': 'Telnet 协议以明文方式传输所有数据，包括认证凭据。',
                'solution': '禁用 Telnet 服务，改用 SSH 进行安全的远程管理。',
                'cve': 'N/A'
            })

        return vulnerabilities

    def quick_scan(self, target):
        """
        快速扫描常见端口

        Args:
            target: 目标IP或域名

        Returns:
            dict: 扫描结果
        """
        common_ports = '21,22,23,25,53,80,110,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,27017'
        return self.scan(target, ports=common_ports, arguments='-sV -T4')

    def full_scan(self, target):
        """
        全端口扫描

        Args:
            target: 目标IP或域名

        Returns:
            dict: 扫描结果
        """
        return self.scan(target, ports='1-65535', arguments='-sV -T4')

    @staticmethod
    def get_scan_summary(result):
        """
        生成扫描摘要

        Args:
            result: 扫描结果

        Returns:
            dict: 扫描摘要
        """
        if not result.get('success'):
            return {
                'status': 'failed',
                'message': result.get('error', '扫描失败')
            }

        open_ports_count = len(result.get('open_ports', []))
        vulns = result.get('vulnerabilities', [])

        high_risk = len([v for v in vulns if v['risk'] == 'high'])
        mid_risk = len([v for v in vulns if v['risk'] == 'mid'])
        low_risk = len([v for v in vulns if v['risk'] == 'low'])

        return {
            'status': 'success',
            'target': result.get('target'),
            'scan_time': result.get('scan_time'),
            'open_ports_count': open_ports_count,
            'vulnerability_count': len(vulns),
            'high_risk': high_risk,
            'mid_risk': mid_risk,
            'low_risk': low_risk,
            'risk_level': 'high' if high_risk > 0 else ('mid' if mid_risk > 0 else 'low')
        }
