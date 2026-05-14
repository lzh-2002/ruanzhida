# -*- coding: utf-8 -*-
"""
网络连接测试脚本
"""

import requests

# 测试配置
API_KEY = "sk-BmyaJPia5n8iPrWiBQ8GfD5ZjBIbdBogtUcfYCCS54lRtFCQ"
PROXY_URL = "http://www.boxying.com"
API_BASE_URL = "https://api.openai.com/v1"

def test_direct_connection():
    """测试直接连接 OpenAI API"""
    print("=== 测试直接连接 ===")
    try:
        headers = {"Authorization": f"Bearer {API_KEY}"}
        response = requests.get(f"{API_BASE_URL}/models", headers=headers, timeout=10)
        print(f"状态码: {response.status_code}")
        print(f"响应: {response.text[:500]}")
        return True
    except Exception as e:
        print(f"错误: {e}")
        return False

def test_proxy_connection():
    """测试通过代理连接"""
    print("\n=== 测试通过代理连接 ===")
    try:
        headers = {"Authorization": f"Bearer {API_KEY}"}
        proxies = {
            "http": PROXY_URL,
            "https": PROXY_URL
        }
        response = requests.get(f"{API_BASE_URL}/models", headers=headers, proxies=proxies, timeout=10)
        print(f"状态码: {response.status_code}")
        print(f"响应: {response.text[:500]}")
        return True
    except Exception as e:
        print(f"错误: {e}")
        return False

def test_proxy_only():
    """测试代理服务器是否可达"""
    print("\n=== 测试代理服务器 ===")
    try:
        # 测试代理服务器本身
        response = requests.get("http://www.example.com", proxies={"http": PROXY_URL, "https": PROXY_URL}, timeout=10)
        print(f"状态码: {response.status_code}")
        print(f"响应: {response.text[:500]}")
        return True
    except Exception as e:
        print(f"错误: {e}")
        return False

if __name__ == "__main__":
    print("网络连接测试开始...")
    
    # 测试1: 直接连接
    test_direct_connection()
    
    # 测试2: 通过代理连接
    test_proxy_connection()
    
    # 测试3: 测试代理服务器
    test_proxy_only()
    
    print("\n测试完成")