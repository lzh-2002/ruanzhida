# -*- coding: utf-8 -*-
"""
数据库模型定义
包含用户、扫描任务、漏洞、系统日志、配置等模型
"""

from datetime import datetime
from extensions import db


class User(db.Model):
    """用户模型"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, comment='用户名')
    email = db.Column(db.String(120), unique=True, nullable=True, comment='邮箱')
    password_hash = db.Column(db.String(256), nullable=False, comment='密码哈希')
    role = db.Column(db.String(20), default='user', comment='角色: user/admin')
    status = db.Column(db.String(20), default='active', comment='状态: active/banned')
    created_at = db.Column(db.DateTime, default=datetime.utcnow, comment='创建时间')
    last_login = db.Column(db.DateTime, comment='最后登录时间')

    # 关联
    scan_tasks = db.relationship('ScanTask', backref='user', lazy='dynamic')
    system_logs = db.relationship('SystemLog', backref='user', lazy='dynamic')

    def __repr__(self):
        return f'<User {self.username}>'

    def is_admin(self):
        """检查是否为管理员"""
        return self.role == 'admin'

    def is_active(self):
        """检查账号是否激活"""
        return self.status == 'active'


class ScanTask(db.Model):
    """扫描任务模型"""
    __tablename__ = 'scan_tasks'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, comment='用户ID')
    target_ip = db.Column(db.String(255), nullable=False, comment='目标IP/域名')
    ports_config = db.Column(db.String(500), default='1-1000', comment='端口配置')
    status = db.Column(db.String(20), default='pending', comment='状态: pending/running/completed/failed')
    protocol = db.Column(db.String(10), default='tcp', comment='协议: tcp/udp')
    web_scan = db.Column(db.Boolean, default=False, comment='是否启用Web漏洞扫描')
    vuln_type = db.Column(db.String(20), default='protocol', comment='漏洞类型: protocol/system/application')
    result_json = db.Column(db.Text, comment='扫描结果JSON')
    ai_summary = db.Column(db.Text, comment='AI生成的摘要')
    pdf_path = db.Column(db.String(500), comment='PDF报告路径')
    created_at = db.Column(db.DateTime, default=datetime.utcnow, comment='创建时间')
    completed_at = db.Column(db.DateTime, comment='完成时间')
    is_deleted = db.Column(db.Boolean, default=False, comment='是否已删除(回收站)')
    deleted_at = db.Column(db.DateTime, comment='删除时间')

    # 关联
    vulnerabilities = db.relationship('Vulnerability', backref='task', lazy='dynamic', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<ScanTask {self.id} - {self.target_ip}>'

    def get_status_text(self):
        """获取状态文本"""
        status_map = {
            'pending': '等待中',
            'running': '扫描中',
            'completed': '已完成',
            'failed': '失败'
        }
        return status_map.get(self.status, '未知')


class Vulnerability(db.Model):
    """漏洞模型"""
    __tablename__ = 'vulnerabilities'

    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('scan_tasks.id'), nullable=False, comment='任务ID')
    risk_level = db.Column(db.String(10), default='low', comment='风险等级: high/mid/low')
    name = db.Column(db.String(255), nullable=False, comment='漏洞名称')
    description = db.Column(db.Text, comment='漏洞描述')
    solution = db.Column(db.Text, comment='修复建议')
    cve_id = db.Column(db.String(50), comment='CVE编号')
    port = db.Column(db.Integer, comment='相关端口')
    service = db.Column(db.String(100), comment='相关服务')
    created_at = db.Column(db.DateTime, default=datetime.utcnow, comment='创建时间')

    def __repr__(self):
        return f'<Vulnerability {self.name}>'

    def get_risk_color(self):
        """获取风险等级对应的颜色"""
        color_map = {
            'high': 'danger',
            'mid': 'warning',
            'low': 'info'
        }
        return color_map.get(self.risk_level, 'secondary')

    def get_risk_text(self):
        """获取风险等级文本"""
        text_map = {
            'high': '高危',
            'mid': '中危',
            'low': '低危'
        }
        return text_map.get(self.risk_level, '未知')


class SystemLog(db.Model):
    """系统日志模型"""
    __tablename__ = 'system_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), comment='用户ID')
    action = db.Column(db.String(255), nullable=False, comment='操作描述')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, comment='时间戳')
    ip_address = db.Column(db.String(50), comment='IP地址')
    details = db.Column(db.Text, comment='详细信息')

    def __repr__(self):
        return f'<SystemLog {self.action}>'


class Config(db.Model):
    """系统配置模型"""
    __tablename__ = 'configs'

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False, comment='配置键')
    value = db.Column(db.String(500), comment='配置值')
    description = db.Column(db.String(255), comment='配置描述')
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, comment='更新时间')

    def __repr__(self):
        return f'<Config {self.key}={self.value}>'

    @staticmethod
    def get_value(key, default=None):
        """获取配置值"""
        config = Config.query.filter_by(key=key).first()
        return config.value if config else default

    @staticmethod
    def set_value(key, value, description=None):
        """设置配置值"""
        config = Config.query.filter_by(key=key).first()
        if config:
            config.value = value
            if description:
                config.description = description
        else:
            config = Config(key=key, value=value, description=description)
            db.session.add(config)
        db.session.commit()
        return config
