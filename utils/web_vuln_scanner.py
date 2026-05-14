# -*- coding: utf-8 -*-
"""
Web 漏洞扫描模块
支持检测常见的 Web 应用漏洞：
- SQL注入 (SQL Injection)
- 跨站脚本 (XSS)
- 目录遍历 (Directory Traversal)
- 命令注入 (Command Injection)
- SSRF (服务端请求伪造)
- 文件上传漏洞
- 敏感信息泄露
- CSRF 防护缺失
"""

import re
import requests
import urllib.parse
import socket
from datetime import datetime

# 禁用 SSL 警告
requests.packages.urllib3.disable_warnings()

# SQL注入检测payload
SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT 1,2,3--",
    "' AND SLEEP(5)--",
    "\" OR \"1\"=\"1",
    "1' OR '1'='1",
    "' OR 0=0 #",
    "' OR 'a'='a",
]

# XSS检测payload
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "'><script>alert(1)</script>",
    "\" onmouseover=alert(1) \"",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
]

# 目录遍历payload
DIR_TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "..\\..\\windows\\system32\\config\\sam",
    "../../etc/hosts",
    "%2e%2e/%2e%2e/etc/passwd",
    "....//....//etc/passwd",
]

# 命令注入payload
COMMAND_INJECTION_PAYLOADS = [
    "; ls",
    "| ls",
    "; id",
    "| id",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "&& ls",
    "|| ls",
    "`ls`",
    "$(ls)",
]

# SSRF检测payload
SSRF_PAYLOADS = [
    "http://127.0.0.1:80",
    "http://localhost:80",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]:80",
    "file:///etc/passwd",
    "gopher://127.0.0.1:25/xHELO",
]

# 敏感文件路径
SENSITIVE_PATHS = [
    "/.git/config",
    "/.env",
    "/config.php",
    "/wp-config.php",
    "/admin/config.php",
    "/backup.sql",
    "/dump.sql",
    "/robots.txt",
    "/sitemap.xml",
    "/phpinfo.php",
    "/info.php",
    "/.htaccess",
    "/.htpasswd",
]


class WebVulnScanner:
    """
    Web 漏洞扫描器类
    """

    def __init__(self, timeout=10, user_agent=None):
        self.timeout = timeout
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.session = requests.Session()
        self.session.timeout = timeout
        self.session.headers.update({'User-Agent': self.user_agent})
        self.session.verify = False  # 禁用SSL验证，便于测试

    def _make_request(self, url, method='GET', params=None, data=None, headers=None):
        """
        发送HTTP请求并返回响应
        """
        try:
            if method.upper() == 'POST':
                response = self.session.post(url, data=data, params=params, headers=headers, timeout=self.timeout)
            else:
                response = self.session.get(url, params=params, headers=headers, timeout=self.timeout)
            return response
        except requests.exceptions.RequestException as e:
            return None

    def detect_sql_injection(self, url, params):
        """
        检测SQL注入漏洞
        """
        vulnerabilities = []
        
        for param_name, param_value in params.items():
            for payload in SQL_INJECTION_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = payload
                
                try:
                    response = self._make_request(url, params=test_params)
                    if response:
                        # 检测SQL错误信息
                        sql_errors = [
                            "SQL syntax", "mysql_fetch", "mysql_num_rows", 
                            "ORA-", "PostgreSQL", "Microsoft SQL",
                            "Unclosed quotation", "syntax error",
                            "Warning: mysql", "Fatal error"
                        ]
                        
                        for error in sql_errors:
                            if error.lower() in response.text.lower():
                                vulnerabilities.append({
                                    'name': 'SQL注入漏洞',
                                    'cve': 'CWE-89',
                                    'risk': 'high',
                                    'param': param_name,
                                    'payload': payload,
                                    'description': f"参数 '{param_name}' 存在SQL注入漏洞，可被利用执行恶意SQL语句。",
                                    'solution': '使用参数化查询（Prepared Statements），对用户输入进行严格过滤和验证。'
                                })
                                break
                                
                        # 检测布尔盲注（响应时间差异）
                        if "' AND SLEEP(5)--" in payload:
                            if response.elapsed.total_seconds() >= 5:
                                vulnerabilities.append({
                                    'name': 'SQL盲注漏洞（时间型）',
                                    'cve': 'CWE-89',
                                    'risk': 'high',
                                    'param': param_name,
                                    'payload': payload,
                                    'description': f"参数 '{param_name}' 存在时间盲注漏洞，攻击者可通过时间延迟判断数据库信息。",
                                    'solution': '使用参数化查询，避免直接将用户输入拼接到SQL语句中。'
                                })
                                
                except Exception as e:
                    continue
        
        return vulnerabilities

    def detect_xss(self, url, params):
        """
        检测XSS跨站脚本漏洞
        """
        vulnerabilities = []
        
        for param_name, param_value in params.items():
            for payload in XSS_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = payload
                
                try:
                    response = self._make_request(url, params=test_params)
                    if response:
                        # 检测payload是否被原样返回
                        if payload in response.text:
                            vulnerabilities.append({
                                'name': 'XSS跨站脚本漏洞',
                                'cve': 'CWE-79',
                                'risk': 'high',
                                'param': param_name,
                                'payload': payload,
                                'description': f"参数 '{param_name}' 存在XSS漏洞，攻击者可注入恶意脚本。",
                                'solution': '对输出进行HTML实体编码，使用安全的模板引擎，实施CSP策略。'
                            })
                            
                except Exception as e:
                    continue
        
        return vulnerabilities

    def detect_directory_traversal(self, url):
        """
        检测目录遍历漏洞
        """
        vulnerabilities = []
        
        for traversal in DIR_TRAVERSAL_PAYLOADS:
            test_url = urllib.parse.urljoin(url, traversal)
            
            try:
                response = self._make_request(test_url)
                if response and response.status_code == 200:
                    # 检测敏感文件特征
                    sensitive_patterns = [
                        "root:x:", "nobody:x:",  # /etc/passwd特征
                        "SYSTEM\\CurrentControlSet",  # Windows SAM特征
                        "[mysqld]", "[database]"  # 配置文件特征
                    ]
                    
                    for pattern in sensitive_patterns:
                        if pattern in response.text:
                            vulnerabilities.append({
                                'name': '目录遍历漏洞',
                                'cve': 'CWE-22',
                                'risk': 'high',
                                'path': traversal,
                                'description': f"存在目录遍历漏洞，可访问敏感文件: {traversal}",
                                'solution': '对用户输入的路径进行严格验证，禁止使用..等特殊字符。'
                            })
                            break
                            
            except Exception as e:
                continue
        
        return vulnerabilities

    def detect_command_injection(self, url, params):
        """
        检测命令注入漏洞
        """
        vulnerabilities = []
        
        for param_name, param_value in params.items():
            for payload in COMMAND_INJECTION_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = payload
                
                try:
                    response = self._make_request(url, params=test_params)
                    if response:
                        # 检测命令执行结果
                        cmd_results = [
                            "root@", "uid=", "gid=", "bin:", "sbin:",
                            "total ", "drwxr", "-rw-r"
                        ]
                        
                        for result in cmd_results:
                            if result in response.text:
                                vulnerabilities.append({
                                    'name': '命令注入漏洞',
                                    'cve': 'CWE-78',
                                    'risk': 'high',
                                    'param': param_name,
                                    'payload': payload,
                                    'description': f"参数 '{param_name}' 存在命令注入漏洞，可执行系统命令。",
                                    'solution': '禁止将用户输入直接传递给系统命令，使用白名单验证。'
                                })
                                break
                                
                except Exception as e:
                    continue
        
        return vulnerabilities

    def detect_ssrf(self, url, params):
        """
        检测SSRF（服务端请求伪造）漏洞
        """
        vulnerabilities = []
        
        for param_name, param_value in params.items():
            for payload in SSRF_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = payload
                
                try:
                    response = self._make_request(url, params=test_params)
                    if response:
                        # 检测是否能访问内部服务
                        if response.status_code == 200:
                            # 检查是否是内部服务响应
                            internal_patterns = [
                                "Apache", "nginx", "Welcome to",
                                "It works!", "Microsoft-IIS"
                            ]
                            
                            for pattern in internal_patterns:
                                if pattern in response.text:
                                    vulnerabilities.append({
                                        'name': 'SSRF服务端请求伪造',
                                        'cve': 'CWE-918',
                                        'risk': 'high',
                                        'param': param_name,
                                        'payload': payload,
                                        'description': f"参数 '{param_name}' 存在SSRF漏洞，可访问内部服务。",
                                        'solution': '对URL参数进行白名单验证，禁止访问内网IP和敏感协议。'
                                    })
                                    break
                            
                except Exception as e:
                    continue
        
        return vulnerabilities

    def detect_sensitive_files(self, url):
        """
        检测敏感文件泄露
        """
        vulnerabilities = []
        
        for path in SENSITIVE_PATHS:
            test_url = urllib.parse.urljoin(url, path)
            
            try:
                response = self._make_request(test_url)
                if response and response.status_code == 200:
                    # 检测文件内容特征
                    content_length = len(response.content)
                    if content_length > 0:
                        vulnerabilities.append({
                            'name': '敏感文件泄露',
                            'cve': 'CWE-538',
                            'risk': 'mid',
                            'path': path,
                            'description': f"发现可访问的敏感文件: {path}",
                            'solution': '限制敏感文件的访问权限，禁止直接访问配置文件和备份文件。'
                        })
                        
            except Exception as e:
                continue
        
        return vulnerabilities

    def detect_csrf(self, url, html_content):
        """
        检测CSRF防护缺失
        """
        vulnerabilities = []
        
        # 检查表单是否包含CSRF token
        csrf_patterns = [
            r'<input[^>]*name=["\']csrf[^>]*>',
            r'<input[^>]*name=["\']token[^>]*>',
            r'<meta[^>]*csrf-token[^>]*>',
            r'csrfToken',
            r'_csrf'
        ]
        
        has_csrf = any(re.search(pattern, html_content, re.IGNORECASE) for pattern in csrf_patterns)
        
        if not has_csrf:
            # 查找表单
            forms = re.findall(r'<form[^>]*>', html_content, re.IGNORECASE)
            if forms:
                vulnerabilities.append({
                    'name': 'CSRF防护缺失',
                    'cve': 'CWE-352',
                    'risk': 'mid',
                    'description': '页面表单缺少CSRF防护机制，可能导致跨站请求伪造攻击。',
                    'solution': '为所有表单添加CSRF token验证，使用SameSite Cookie属性。'
                })
        
        return vulnerabilities

    def analyze_headers(self, response):
        """
        分析HTTP响应头安全配置
        """
        vulnerabilities = []
        headers = response.headers
        
        # 检查安全相关头
        security_headers = {
            'X-Content-Type-Options': '缺少X-Content-Type-Options头，可能导致MIME类型混淆攻击',
            'X-Frame-Options': '缺少X-Frame-Options头，可能被点击劫持',
            'X-XSS-Protection': '缺少X-XSS-Protection头，浏览器XSS保护可能被禁用',
            'Content-Security-Policy': '缺少Content-Security-Policy头，无法有效防止XSS',
            'Strict-Transport-Security': '缺少HSTS头，无法强制HTTPS连接',
            'Referrer-Policy': '缺少Referrer-Policy头，可能泄露敏感信息',
            'Permissions-Policy': '缺少Permissions-Policy头，无法限制浏览器特性访问'
        }
        
        for header, description in security_headers.items():
            if header not in headers:
                vulnerabilities.append({
                    'name': f'{header} 头缺失',
                    'cve': 'CWE-693',
                    'risk': 'low',
                    'description': description,
                    'solution': f'添加 {header} HTTP响应头以增强安全性。'
                })
        
        # 检查Server头是否暴露版本信息
        if 'Server' in headers:
            server_header = headers['Server']
            if re.search(r'/[\d.]+', server_header):
                vulnerabilities.append({
                    'name': 'Server头暴露版本信息',
                    'cve': 'CWE-200',
                    'risk': 'low',
                    'description': f"Server头暴露了服务器版本: {server_header}",
                    'solution': '配置服务器隐藏或模糊Server头信息。'
                })
        
        return vulnerabilities

    def scan(self, url, params=None):
        """
        执行完整的Web漏洞扫描
        """
        result = {
            'url': url,
            'scan_time': datetime.now().isoformat(),
            'vulnerabilities': [],
            'info': []
        }
        
        # 确保URL以http/https开头
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # 默认参数（用于测试）
        if params is None:
            params = {'id': '1', 'q': 'test', 'page': '1'}
        
        # 1. 获取基础页面
        try:
            response = self._make_request(url)
            if not response:
                result['error'] = '无法访问目标URL'
                return result
            
            html_content = response.text
            
            # 分析响应头
            header_vulns = self.analyze_headers(response)
            result['vulnerabilities'].extend(header_vulns)
            
            # 检测CSRF
            csrf_vulns = self.detect_csrf(url, html_content)
            result['vulnerabilities'].extend(csrf_vulns)
            
            # 检测敏感文件
            sensitive_vulns = self.detect_sensitive_files(url)
            result['vulnerabilities'].extend(sensitive_vulns)
            
            # 如果有参数，进行注入测试
            if params:
                # SQL注入检测
                sql_vulns = self.detect_sql_injection(url, params)
                result['vulnerabilities'].extend(sql_vulns)
                
                # XSS检测
                xss_vulns = self.detect_xss(url, params)
                result['vulnerabilities'].extend(xss_vulns)
                
                # 命令注入检测
                cmd_vulns = self.detect_command_injection(url, params)
                result['vulnerabilities'].extend(cmd_vulns)
                
                # SSRF检测
                ssrf_vulns = self.detect_ssrf(url, params)
                result['vulnerabilities'].extend(ssrf_vulns)
            
            # 目录遍历检测（不需要参数）
            dir_vulns = self.detect_directory_traversal(url)
            result['vulnerabilities'].extend(dir_vulns)
            
            # 添加基本信息
            result['info'] = {
                'status_code': response.status_code,
                'content_length': len(html_content),
                'server': response.headers.get('Server', 'Unknown'),
                'title': re.search(r'<title>([^<]+)</title>', html_content, re.IGNORECASE)
            }
            
            if result['info']['title']:
                result['info']['title'] = result['info']['title'].group(1)
            
            result['success'] = True
            
        except Exception as e:
            result['success'] = False
            result['error'] = str(e)
        
        return result

    def quick_scan(self, url):
        """
        快速扫描（仅检测高危漏洞）
        """
        result = {
            'url': url,
            'scan_time': datetime.now().isoformat(),
            'vulnerabilities': [],
            'info': []
        }
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        try:
            response = self._make_request(url)
            if not response:
                result['error'] = '无法访问目标URL'
                return result
            
            html_content = response.text
            
            # 快速检测：敏感文件、目录遍历、响应头
            sensitive_vulns = self.detect_sensitive_files(url)
            result['vulnerabilities'].extend(sensitive_vulns)
            
            dir_vulns = self.detect_directory_traversal(url)
            result['vulnerabilities'].extend(dir_vulns)
            
            header_vulns = self.analyze_headers(response)
            result['vulnerabilities'].extend(header_vulns)
            
            result['success'] = True
            
        except Exception as e:
            result['success'] = False
            result['error'] = str(e)
        
        return result


# 测试函数
def test_web_scanner():
    """测试Web漏洞扫描器"""
    scanner = WebVulnScanner()
    
    # 测试目标
    test_url = "http://127.0.0.1:8081"
    
    print(f"正在扫描: {test_url}")
    result = scanner.scan(test_url, {'id': '1', 'page': '2'})
    
    print(f"\n扫描结果:")
    print(f"成功: {result['success']}")
    print(f"发现漏洞数: {len(result.get('vulnerabilities', []))}")
    
    for vuln in result.get('vulnerabilities', []):
        print(f"\n[-] {vuln['name']}")
        print(f"    风险等级: {vuln['risk']}")
        print(f"    CVE: {vuln['cve']}")
        print(f"    描述: {vuln['description']}")


if __name__ == '__main__':
    test_web_scanner()