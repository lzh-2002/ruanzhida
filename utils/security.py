# -*- coding: utf-8 -*-
"""
密码安全模块
使用 werkzeug.security 进行密码哈希和验证
"""

from werkzeug.security import generate_password_hash, check_password_hash


def hash_password(password):
    """
    对密码进行哈希加盐处理

    Args:
        password: 原始密码

    Returns:
        str: 哈希后的密码
    """
    return generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)


def verify_password(password_hash, password):
    """
    验证密码是否正确

    Args:
        password_hash: 存储的密码哈希
        password: 用户输入的密码

    Returns:
        bool: 密码是否正确
    """
    return check_password_hash(password_hash, password)
