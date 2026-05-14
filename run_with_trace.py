# -*- coding: utf-8 -*-
"""
错误追踪脚本 - 获取完整堆栈信息
"""

import sys
import traceback

# 设置详细的异常钩子
def detailed_excepthook(exc_type, exc_value, exc_tb):
    print("\n" + "=" * 70)
    print("捕获到异常！完整堆栈信息：")
    print("=" * 70)
    traceback.print_exception(exc_type, exc_value, exc_tb)
    print("=" * 70)

sys.excepthook = detailed_excepthook

# 尝试导入并运行 app
print("正在启动应用...")
print("-" * 70)

from app import app, init_db

init_db()
app.run(debug=True, host='0.0.0.0', port=5000)
