# -*- coding: utf-8 -*-
"""
数据库扩展初始化模块
用于创建全局数据库实例，避免循环导入
"""

from flask_sqlalchemy import SQLAlchemy

# 创建全局数据库实例
db = SQLAlchemy()
