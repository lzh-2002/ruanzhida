# -*- coding: utf-8 -*-
"""
测试 nmap 扫描器是否正常工作
"""

import sys
import os

# 确保能找到 utils 模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_nmap():
    """测试 nmap 是否可用"""
    print("=" * 50)
    print("测试 Nmap 扫描器")
    print("=" * 50)

    # 测试 1: 导入模块
    print("\n[1] 导入 scanner 模块...")
    try:
        from utils.scanner import PortScanner, find_nmap_path
        print("    成功!")
    except Exception as e:
        print(f"    失败: {e}")
        return False

    # 测试 2: 查找 nmap 路径
    print("\n[2] 查找 nmap 路径...")
    nmap_path = find_nmap_path()
    if nmap_path:
        print(f"    找到: {nmap_path}")
    else:
        print("    未找到 nmap，请确保已安装")
        return False

    # 测试 3: 初始化扫描器
    print("\n[3] 初始化 PortScanner...")
    try:
        scanner = PortScanner()
        print("    成功!")
    except Exception as e:
        print(f"    失败: {e}")
        return False

    # 测试 4: 执行简单扫描
    print("\n[4] 测试扫描 localhost:80...")
    try:
        result = scanner.scan('127.0.0.1', ports='80', arguments='-sT -T4')
        print(f"    扫描完成!")
        print(f"    结果: {result.get('success', False)}")
        if result.get('open_ports'):
            print(f"    开放端口: {[p['port'] for p in result['open_ports']]}")
        else:
            print("    未发现开放端口 (这是正常的，如果80端口未开放)")
    except Exception as e:
        print(f"    扫描出错: {e}")
        return False

    print("\n" + "=" * 50)
    print("所有测试通过! Nmap 工作正常。")
    print("=" * 50)
    return True


if __name__ == '__main__':
    success = test_nmap()
    sys.exit(0 if success else 1)
