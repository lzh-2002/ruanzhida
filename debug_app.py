# -*- coding: utf-8 -*-
"""
调试启动脚本 - 用于定位应用上下文错误
"""

import sys
import traceback

print("=" * 60)
print("开始调试导入过程...")
print("=" * 60)

try:
    print("\n[1] 导入 os, json, threading...")
    import os
    import json
    import threading
    from datetime import datetime, date
    from functools import wraps
    from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
    print("    成功!")

    print("\n[2] 导入 Flask...")
    from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort, Response, has_app_context
    print("    成功!")

    print("\n[3] 导入 extensions (db)...")
    from extensions import db
    print("    成功!")

    print("\n[4] 创建 Flask app...")
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'test-key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vuln_scanner.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    print("    成功!")

    print("\n[5] 初始化 db.init_app(app)...")
    db.init_app(app)
    print("    成功!")

    print("\n[6] 导入 models...")
    from models import User, ScanTask, Vulnerability, SystemLog, Config
    print("    成功!")

    print("\n[7] 导入 utils.security...")
    from utils.security import hash_password, verify_password
    print("    成功!")

    print("\n[8] 导入 utils.scanner...")
    from utils.scanner import PortScanner, validate_target
    print("    成功!")

    print("\n[9] 导入 utils.ai_helper...")
    from utils.ai_helper import AIClient, analyze_vulnerability, generate_report_summary, chat_with_ai
    print("    成功!")

    print("\n[10] 测试应用上下文...")
    with app.app_context():
        print("    进入应用上下文成功!")

        print("\n[11] 测试数据库查询...")
        try:
            db.create_all()
            user_count = User.query.count()
            print(f"    数据库查询成功! 用户数: {user_count}")
        except Exception as e:
            print(f"    数据库查询失败: {e}")

    print("\n" + "=" * 60)
    print("所有导入测试通过!")
    print("=" * 60)

    print("\n现在尝试启动完整应用...")
    print("-" * 60)

    # 现在导入完整的 app
    import app as main_app

except Exception as e:
    print(f"\n错误发生!")
    print("=" * 60)
    traceback.print_exc()
    print("=" * 60)
    sys.exit(1)
