# -*- coding: utf-8 -*-
"""
AI 助手模块
使用 DeepSeek API 提供漏洞分析和报告生成功能
"""

import json
import requests
import time


class AIClient:
    """
    AI 客户端类
    封装 DeepSeek API 调用（使用 requests 直接调用）
    """

    # DeepSeek API 配置
    API_KEY = "sk-1ab2e930b35a4d288d02a56f077d7ea6"
    MODEL_NAME = "deepseek-v4-pro"
    API_BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
    
    # 代理配置
    USE_PROXY = False
    PROXY_URL = ""

    def __init__(self):
        """初始化 AI 客户端"""
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.API_KEY}"
        }
        
        self.session = requests.Session()
        self.session.trust_env = False

    def _call_api(self, messages, max_retries=2):
        """
        调用 AI API（带重试机制）
        """
        url = f"{self.API_BASE_URL}/chat/completions"
        
        payload = {
            "model": self.MODEL_NAME,
            "messages": messages,
            "temperature": 0.7,
            "max_tokens": 2000
        }

        for attempt in range(max_retries + 1):
            try:
                response = self.session.post(url, headers=self.headers, json=payload, timeout=120)
                response.raise_for_status()
                
                data = response.json()
                result = data["choices"][0]["message"]["content"].strip()
                
                if result:
                    return result
                else:
                    return "AI 未返回有效响应。"

            except requests.exceptions.HTTPError as e:
                error_data = response.json() if response else {}
                error_msg = error_data.get("error", {}).get("message", str(e))
                if "invalid api key" in error_msg.lower() or "authentication" in error_msg.lower():
                    return "API 密钥无效，请检查您的 OpenAI API Key。"
                elif "rate limit" in error_msg.lower():
                    if attempt < max_retries:
                        time.sleep(2 ** attempt)
                        continue
                    return "API 调用频率超限，请稍后重试或升级您的订阅。"
                else:
                    if attempt < max_retries:
                        time.sleep(1)
                        continue
                    return f"AI 服务错误：{error_msg}"
            except requests.exceptions.Timeout:
                if attempt < max_retries:
                    time.sleep(1)
                    continue
                return "AI 服务响应超时，请稍后重试。"
            except requests.exceptions.ConnectionError:
                if attempt < max_retries:
                    time.sleep(1)
                    continue
                return "网络连接失败，请检查网络设置。"
            except Exception as e:
                if attempt < max_retries:
                    time.sleep(1)
                    continue
                return f"AI 服务调用异常：{str(e)}"
        
        return "AI 服务调用失败，已达到最大重试次数。"

    def analyze_vulnerability(self, vuln_desc):
        """分析漏洞并提供修复建议"""
        prompt = f"""你是一名资深网络安全专家。请分析以下漏洞信息，并提供详细的修复建议：

漏洞信息：
{vuln_desc}

请从以下几个方面进行分析：
1. 漏洞原理：简要解释这个漏洞是如何产生的
2. 风险评估：分析该漏洞可能造成的危害
3. 利用场景：攻击者可能如何利用该漏洞
4. 修复方案：提供具体、可操作的修复步骤
5. 预防措施：如何避免类似漏洞再次出现

请用专业但易懂的语言回答。"""

        messages = [{"role": "user", "content": prompt}]
        return self._call_api(messages)

    def generate_report_summary(self, scan_data):
        """生成扫描报告摘要"""
        if isinstance(scan_data, dict):
            scan_data = json.dumps(scan_data, ensure_ascii=False, indent=2)

        prompt = f"""你是一名网络安全分析师。请根据以下端口扫描结果，生成一份简洁的安全评估摘要：

扫描结果：
{scan_data}

请提供：
1. 总体安全评估（用一句话概括安全状况）
2. 主要发现（列出最重要的 3-5 个发现）
3. 风险等级（高/中/低）及理由
4. 优先处理建议（最需要立即处理的问题）
5. 长期安全建议

请确保报告简洁明了，便于非技术人员理解。"""

        messages = [{"role": "user", "content": prompt}]
        return self._call_api(messages)

    def chat_with_ai(self, question, context=None):
        """与 AI 进行自然语言对话"""
        system_prompt = """你是一名专业的网络安全顾问，专注于漏洞检测、端口扫描分析和网络安全防护。
你可以回答关于：
- 网络安全基础知识
- 漏洞分析和修复
- 端口服务安全配置
- 安全最佳实践
- 渗透测试相关问题

请用专业但易于理解的方式回答问题。如果问题超出你的专业领域，请诚实告知。"""

        messages = [{"role": "system", "content": system_prompt}]

        if context:
            messages.append({
                "role": "user",
                "content": f"背景信息：{context}\n\n问题：{question}"
            })
        else:
            messages.append({
                "role": "user",
                "content": question
            })

        return self._call_api(messages)

    def analyze_port_risk(self, port, service, version=None):
        """分析特定端口的安全风险"""
        version_info = f"，版本：{version}" if version else ""

        prompt = f"""请分析以下开放端口的安全风险：

端口：{port}
服务：{service}{version_info}

请提供：
1. 该端口/服务的常见用途
2. 潜在的安全风险
3. 已知的相关漏洞（如有）
4. 安全配置建议
5. 是否建议在生产环境开放"""

        messages = [{"role": "user", "content": prompt}]
        return self._call_api(messages)


_client = None


def get_ai_client():
    """获取 AI 客户端单例"""
    global _client
    if _client is None:
        _client = AIClient()
    return _client


def analyze_vulnerability(vuln_desc):
    """分析漏洞"""
    return get_ai_client().analyze_vulnerability(vuln_desc)


def generate_report_summary(scan_data):
    """生成报告摘要"""
    return get_ai_client().generate_report_summary(scan_data)


def chat_with_ai(question, context=None):
    """AI 对话"""
    return get_ai_client().chat_with_ai(question, context)
