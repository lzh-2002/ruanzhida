from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import requests
import hashlib
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import io
from openai import OpenAI
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vulnerabilities.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 大模型 API配置
DEEPSEEK_API_KEY = os.environ.get('DEEPSEEK_API_KEY', 'sk-apbrrlwzlihcpogrjrffayllxaeybkmflbjpysoakrtyvikc')
DEEPSEEK_BASE_URL = os.environ.get('DEEPSEEK_BASE_URL', 'https://api.siliconflow.cn/v1/chat/completions')

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

    def __repr__(self):
        return f'<User {self.username}>'

class ScanTask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target_url = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.now)
    completed_at = db.Column(db.DateTime)
    deleted = db.Column(db.Boolean, default=False)
    deleted_at = db.Column(db.DateTime)
    vulnerabilities = db.relationship('Vulnerability', backref='scan_task', lazy=True)

    def __repr__(self):
        return f'<ScanTask {self.target_url}>'

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_task_id = db.Column(db.Integer, db.ForeignKey('scan_task.id'), nullable=False)
    type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=False)
    payload = db.Column(db.String(500))
    found_at = db.Column(db.DateTime, default=datetime.now)

    def __repr__(self):
        return f'<Vulnerability {self.type}>'

class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    username = db.Column(db.String(100), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    detail = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.now)

    def __repr__(self):
        return f'<SystemLog {self.action}>'

class AiAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_task_id = db.Column(db.Integer, db.ForeignKey('scan_task.id'), nullable=False)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey('vulnerability.id'))
    analysis_text = db.Column(db.Text, nullable=False)
    risk_level = db.Column(db.String(20))
    recommendations = db.Column(db.Text)
    attack_vector = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now)

    def __repr__(self):
        return f'<AiAnalysis {self.id}>'

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def log_action(action, detail=None):
    user_id = session.get('user_id')
    username = session.get('username', 'unknown')
    ip_address = request.remote_addr if request else None
    
    log_entry = SystemLog(
        user_id=user_id,
        username=username,
        action=action,
        detail=detail,
        ip_address=ip_address
    )
    db.session.add(log_entry)
    db.session.commit()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def scan_xss(url):
    vulnerabilities = []
    payloads = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
    ]
    
    for payload in payloads:
        try:
            response = requests.get(url + '?q=' + payload, timeout=10)
            if payload in response.text:
                vulnerabilities.append({
                    'type': 'XSS',
                    'severity': 'High',
                    'description': 'Cross-Site Scripting vulnerability detected',
                    'payload': payload
                })
        except:
            pass
    return vulnerabilities

def scan_sql_injection(url):
    vulnerabilities = []
    payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT NULL, NULL, NULL--",
    ]
    
    for payload in payloads:
        try:
            response = requests.get(url + '?id=' + payload, timeout=10)
            if 'SQL' in response.text or 'error' in response.text.lower():
                vulnerabilities.append({
                    'type': 'SQL Injection',
                    'severity': 'Critical',
                    'description': 'SQL Injection vulnerability detected',
                    'payload': payload
                })
        except:
            pass
    return vulnerabilities

def scan_open_redirect(url):
    vulnerabilities = []
    payloads = [
        '?redirect=http://evil.com',
        '?next=http://malicious.com',
    ]
    
    for payload in payloads:
        try:
            response = requests.get(url + payload, timeout=10, allow_redirects=True)
            if response.url and 'evil.com' in response.url:
                vulnerabilities.append({
                    'type': 'Open Redirect',
                    'severity': 'Medium',
                    'description': 'Open Redirect vulnerability detected',
                    'payload': payload
                })
        except:
            pass
    return vulnerabilities

def scan_lfi(url):
    vulnerabilities = []
    payloads = [
        '?file=../../etc/passwd',
        '?file=../../../etc/passwd',
        '?page=../../../../../etc/passwd',
    ]
    
    for payload in payloads:
        try:
            response = requests.get(url + payload, timeout=10)
            if 'root:' in response.text or 'nobody:' in response.text:
                vulnerabilities.append({
                    'type': 'Local File Inclusion',
                    'severity': 'Critical',
                    'description': 'Local File Inclusion vulnerability detected',
                    'payload': payload
                })
        except:
            pass
    return vulnerabilities

def perform_scan(url):
    all_vulnerabilities = []
    all_vulnerabilities.extend(scan_xss(url))
    all_vulnerabilities.extend(scan_sql_injection(url))
    all_vulnerabilities.extend(scan_open_redirect(url))
    all_vulnerabilities.extend(scan_lfi(url))
    return all_vulnerabilities

def call_deepseek_api(vulnerability):
    """调用DeepSeek API进行漏洞分析"""
    try:
        client = OpenAI(
            api_key=DEEPSEEK_API_KEY,
            base_url=DEEPSEEK_BASE_URL
        )
        
        prompt = f"""你是一个专业的网络安全专家。请对以下漏洞进行深度分析，并提供详细的修复建议。

漏洞类型: {vulnerability['type']}
严重程度: {vulnerability['severity']}
描述: {vulnerability['description']}
有效载荷: {vulnerability.get('payload', '无')}

请按以下JSON格式返回分析结果：
{{
    "analysis": "漏洞的详细分析，包括原理、危害、影响范围等",
    "risk_level": "风险等级: Critical/High/Medium/Low",
    "attack_vector": "详细的攻击向量描述，说明攻击者如何利用此漏洞",
    "recommendations": [
        "修复建议1",
        "修复建议2",
        "修复建议3",
        "修复建议4",
        "修复建议5",
        "修复建议6"
    ]
}}

请确保返回的是有效的JSON格式，不要包含任何其他文字说明。"""

        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": "You are a professional cybersecurity expert specialized in vulnerability analysis and remediation."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=2000
        )
        
        import json
        result_text = response.choices[0].message.content.strip()
        
        # 尝试解析JSON，如果失败则使用正则提取
        try:
            # 尝试直接解析
            result = json.loads(result_text)
        except json.JSONDecodeError:
            # 如果失败，尝试提取JSON部分
            import re
            json_match = re.search(r'\{.*\}', result_text, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
            else:
                raise ValueError("无法解析API响应")
        
        return {
            'analysis': result.get('analysis', '分析失败'),
            'risk_level': result.get('risk_level', vulnerability['severity']),
            'attack_vector': result.get('attack_vector', '无法确定攻击向量'),
            'recommendations': result.get('recommendations', ['建议进一步调查此漏洞类型'])
        }
        
    except Exception as e:
        print(f"DeepSeek API调用失败: {str(e)}")
        # API调用失败时返回基于规则的默认分析
        return get_default_analysis(vulnerability)

def get_default_analysis(vulnerability):
    """当API调用失败时返回默认分析"""
    analysis_rules = {
        'XSS': {
            'analysis': '跨站脚本攻击（XSS）是一种常见的Web安全漏洞，攻击者可以通过注入恶意脚本代码到网页中，当用户访问该页面时，脚本会在用户浏览器中执行。这可能导致会话劫持、Cookie窃取、钓鱼攻击等严重后果。',
            'risk_level': 'High',
            'attack_vector': '攻击者通过URL参数、表单输入或其他用户可控的输入点注入恶意JavaScript代码。当应用程序没有对用户输入进行适当的验证和转义时，这些脚本会被浏览器执行。',
            'recommendations': [
                '对所有用户输入进行严格的验证和过滤',
                '使用HTML实体编码对输出进行转义',
                '采用内容安全策略（CSP）限制脚本执行',
                '使用框架自带的XSS防护机制（如React的自动转义）',
                '对URL参数进行白名单验证',
                '使用HttpOnly标志保护Cookie'
            ]
        },
        'SQL Injection': {
            'analysis': 'SQL注入是一种严重的安全漏洞，攻击者可以通过在输入字段中注入恶意SQL语句来操纵数据库。这可能导致数据泄露、数据篡改、甚至完全控制数据库服务器。',
            'risk_level': 'Critical',
            'attack_vector': '攻击者通过在URL参数、表单字段或Cookie中插入SQL代码片段。当应用程序直接将用户输入拼接到SQL查询中而没有进行适当处理时，恶意SQL会被执行。',
            'recommendations': [
                '使用参数化查询（Prepared Statements）',
                '采用ORM框架进行数据库操作',
                '对用户输入进行严格的类型验证',
                '实施最小权限原则，限制数据库用户权限',
                '对SQL错误信息进行脱敏处理',
                '定期进行SQL注入漏洞扫描'
            ]
        },
        'Open Redirect': {
            'analysis': '开放重定向漏洞允许攻击者将用户重定向到恶意网站。虽然本身危害相对较低，但常被用于钓鱼攻击，欺骗用户访问看似可信的恶意网站。',
            'risk_level': 'Medium',
            'attack_vector': '攻击者构造包含恶意URL的链接，当受害者点击时，应用程序会将其重定向到攻击者控制的网站。这种漏洞常被用于绕过安全检查或进行钓鱼攻击。',
            'recommendations': [
                '对重定向URL进行白名单验证',
                '避免使用用户可控的参数进行重定向',
                '使用相对路径而非绝对URL',
                '在重定向前向用户显示确认页面',
                '记录所有重定向操作日志',
                '对可疑重定向进行安全警告'
            ]
        },
        'Local File Inclusion': {
            'analysis': '本地文件包含（LFI）漏洞允许攻击者读取服务器上的敏感文件。这可能导致敏感配置文件泄露、源代码暴露，甚至在某些情况下导致远程代码执行。',
            'risk_level': 'Critical',
            'attack_vector': '攻击者通过操纵文件路径参数，使用../等字符遍历目录结构，访问系统敏感文件。如果应用程序没有正确验证和限制文件路径，攻击者可以读取任意文件。',
            'recommendations': [
                '对文件路径进行严格的白名单验证',
                '使用绝对路径而非相对路径',
                '禁止使用../等目录遍历字符',
                '限制可访问的目录范围',
                '设置正确的文件权限',
                '对敏感文件进行加密存储'
            ]
        }
    }

    return analysis_rules.get(vulnerability['type'], {
        'analysis': f'未知漏洞类型: {vulnerability["type"]}',
        'risk_level': 'Unknown',
        'attack_vector': '无法确定攻击向量',
        'recommendations': ['建议进一步调查此漏洞类型']
    })

def perform_ai_analysis(task_id, vulnerabilities):
    analyses = []
    for vuln in vulnerabilities:
        # 调用DeepSeek API进行分析
        analysis_result = call_deepseek_api(vuln)
        
        analysis = AiAnalysis(
            scan_task_id=task_id,
            analysis_text=analysis_result['analysis'],
            risk_level=analysis_result['risk_level'],
            recommendations='\n'.join(analysis_result['recommendations']),
            attack_vector=analysis_result['attack_vector']
        )
        db.session.add(analysis)
        analyses.append(analysis_result)
    
    db.session.commit()
    return analyses

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        captcha = request.form.get('captcha', '').upper()
        session_captcha = session.get('captcha', '').upper()
        
        if captcha != session_captcha:
            flash('验证码错误', 'danger')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.password == hash_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            log_action('用户登录', f'用户 {username} 登录系统')
            flash('登录成功', 'success')
            return redirect(url_for('index'))
        else:
            flash('用户名或密码错误', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('用户名已存在', 'danger')
            return redirect(url_for('register'))
        
        new_user = User(username=username, password=hash_password(password))
        db.session.add(new_user)
        db.session.commit()
        
        flash('注册成功，请登录', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    username = session.get('username')
    log_action('用户退出', f'用户 {username} 退出系统')
    session.clear()
    flash('已退出登录', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    tasks = ScanTask.query.filter_by(user_id=session['user_id'], deleted=False).order_by(ScanTask.created_at.desc()).all()
    return render_template('index.html', tasks=tasks, username=session['username'])

@app.route('/dashboard')
@login_required
def dashboard():
    total_scans = ScanTask.query.filter_by(user_id=session['user_id']).count()
    completed_scans = ScanTask.query.filter_by(user_id=session['user_id'], status='completed').count()
    total_vulnerabilities = Vulnerability.query.join(ScanTask).filter(ScanTask.user_id == session['user_id']).count()
    
    critical_count = Vulnerability.query.join(ScanTask).filter(
        ScanTask.user_id == session['user_id'],
        Vulnerability.severity == 'Critical'
    ).count()
    high_count = Vulnerability.query.join(ScanTask).filter(
        ScanTask.user_id == session['user_id'],
        Vulnerability.severity == 'High'
    ).count()
    medium_count = Vulnerability.query.join(ScanTask).filter(
        ScanTask.user_id == session['user_id'],
        Vulnerability.severity == 'Medium'
    ).count()
    
    recent_tasks = ScanTask.query.filter_by(user_id=session['user_id']).order_by(ScanTask.created_at.desc()).limit(5).all()
    
    return render_template('dashboard.html', 
                           username=session['username'],
                           total_scans=total_scans,
                           completed_scans=completed_scans,
                           total_vulnerabilities=total_vulnerabilities,
                           critical_count=critical_count,
                           high_count=high_count,
                           medium_count=medium_count,
                           recent_tasks=recent_tasks)

@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    if request.method == 'POST':
        target_url = request.form['target_url']
        
        if not target_url.startswith('http://') and not target_url.startswith('https://'):
            target_url = 'http://' + target_url
        
        task = ScanTask(user_id=session['user_id'], target_url=target_url, status='running')
        db.session.add(task)
        db.session.commit()
        
        vulnerabilities = perform_scan(target_url)
        
        for vuln in vulnerabilities:
            vulnerability = Vulnerability(
                scan_task_id=task.id,
                type=vuln['type'],
                severity=vuln['severity'],
                description=vuln['description'],
                payload=vuln['payload']
            )
            db.session.add(vulnerability)
        
        task.status = 'completed'
        task.completed_at = datetime.now()
        db.session.commit()
        
        perform_ai_analysis(task.id, vulnerabilities)
        
        log_action('漏洞扫描完成', f'扫描目标: {target_url}, 发现漏洞: {len(vulnerabilities)}个')
        flash(f'Scan completed! Found {len(vulnerabilities)} vulnerabilities.', 'success')
        return redirect(url_for('results', task_id=task.id))
    
    return render_template('scan.html', username=session['username'])

@app.route('/results/<int:task_id>')
@login_required
def results(task_id):
    task = ScanTask.query.filter_by(id=task_id, user_id=session['user_id']).first_or_404()
    vulnerabilities = Vulnerability.query.filter_by(scan_task_id=task_id).all()
    ai_analyses = AiAnalysis.query.filter_by(scan_task_id=task_id).all()
    
    vuln_analysis_map = {}
    for i, vuln in enumerate(vulnerabilities):
        if i < len(ai_analyses):
            vuln_analysis_map[vuln.id] = {
                'analysis': ai_analyses[i].analysis_text,
                'risk_level': ai_analyses[i].risk_level,
                'attack_vector': ai_analyses[i].attack_vector,
                'recommendations': ai_analyses[i].recommendations.split('\n')
            }
    
    return render_template('results.html', 
                           task=task, 
                           vulnerabilities=vulnerabilities, 
                           vuln_analysis_map=vuln_analysis_map,
                           username=session['username'])

@app.route('/delete/<int:task_id>')
@login_required
def delete_task(task_id):
    task = ScanTask.query.filter_by(id=task_id, user_id=session['user_id'], deleted=False).first_or_404()
    task.deleted = True
    task.deleted_at = datetime.now()
    db.session.commit()
    flash('扫描任务已移至回收站.', 'info')
    return redirect(url_for('index'))

@app.route('/recycle')
@login_required
def recycle_bin():
    deleted_tasks = ScanTask.query.filter_by(user_id=session['user_id'], deleted=True).order_by(ScanTask.deleted_at.desc()).all()
    return render_template('recycle_bin.html', tasks=deleted_tasks, username=session['username'])

@app.route('/recover/<int:task_id>')
@login_required
def recover_task(task_id):
    task = ScanTask.query.filter_by(id=task_id, user_id=session['user_id'], deleted=True).first_or_404()
    task.deleted = False
    task.deleted_at = None
    db.session.commit()
    flash('扫描任务已恢复.', 'success')
    return redirect(url_for('recycle_bin'))

@app.route('/purge/<int:task_id>')
@login_required
def purge_task(task_id):
    task = ScanTask.query.filter_by(id=task_id, user_id=session['user_id'], deleted=True).first_or_404()
    Vulnerability.query.filter_by(scan_task_id=task_id).delete()
    db.session.delete(task)
    db.session.commit()
    flash('扫描任务已彻底删除.', 'danger')
    return redirect(url_for('recycle_bin'))

@app.route('/clear_recycle')
@login_required
def clear_recycle_bin():
    deleted_tasks = ScanTask.query.filter_by(user_id=session['user_id'], deleted=True).all()
    for task in deleted_tasks:
        Vulnerability.query.filter_by(scan_task_id=task.id).delete()
        db.session.delete(task)
    db.session.commit()
    flash('回收站已清空.', 'info')
    return redirect(url_for('recycle_bin'))

@app.route('/settings')
@login_required
def settings():
    user = User.query.filter_by(id=session['user_id']).first_or_404()
    return render_template('settings.html', user=user, username=session['username'])

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    old_password = request.form['old_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']
    
    user = User.query.filter_by(id=session['user_id']).first_or_404()
    
    if user.password != hash_password(old_password):
        flash('当前密码不正确.', 'danger')
        return redirect(url_for('settings'))
    
    if new_password != confirm_password:
        flash('两次输入的新密码不一致.', 'danger')
        return redirect(url_for('settings'))
    
    user.password = hash_password(new_password)
    db.session.commit()
    flash('密码修改成功.', 'success')
    return redirect(url_for('settings'))

def generate_captcha():
    chars = string.ascii_uppercase + string.digits
    captcha_text = ''.join(random.choice(chars) for _ in range(4))
    session['captcha'] = captcha_text
    
    svg_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="46" viewBox="0 0 100 46">
  <rect width="100" height="46" fill="#ffffff" stroke="#e2e8f0" stroke-width="2" rx="8"/>
  {''.join(f'<text x="{15 + i * 20}" y="{28 + random.randint(-3, 3)}" font-family="Arial, sans-serif" font-size="22" font-weight="bold" fill="rgb({random.randint(30, 100)},{random.randint(30, 100)},{random.randint(30, 100)})" transform="rotate({random.randint(-10, 10)},{15 + i * 20},25)">{captcha_text[i]}</text>' for i in range(4))}
  {''.join(f'<line x1="{random.randint(0, 100)}" y1="{random.randint(0, 46)}" x2="{random.randint(0, 100)}" y2="{random.randint(0, 46)}" stroke="rgb({random.randint(180, 220)},{random.randint(180, 220)},{random.randint(180, 220)})" stroke-width="1"/>' for _ in range(8))}
  {''.join(f'<circle cx="{random.randint(5, 95)}" cy="{random.randint(5, 41)}" r="1" fill="rgb({random.randint(180, 220)},{random.randint(180, 220)},{random.randint(180, 220)})"/>' for _ in range(15))}
</svg>'''
    
    response = make_response(svg_content)
    response.headers['Content-Type'] = 'image/svg+xml'
    return response

@app.route('/captcha')
def captcha():
    return generate_captcha()

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        flash('密码找回功能开发中，请联系管理员', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/users')
@login_required
def users():
    if session.get('username') != 'admin':
        flash('无权访问此页面', 'danger')
        return redirect(url_for('dashboard'))
    users = User.query.all()
    return render_template('users.html', username=session.get('username'), users=users)

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if session.get('username') != 'admin':
        flash('无权执行此操作', 'danger')
        return redirect(url_for('dashboard'))
    username = request.form.get('username')
    password = request.form.get('password')
    
    if User.query.filter_by(username=username).first():
        flash('用户名已存在', 'danger')
        return redirect(url_for('users'))
    
    new_user = User(username=username, password=hash_password(password))
    db.session.add(new_user)
    db.session.commit()
    log_action('添加用户', f'管理员添加用户: {username}')
    flash('用户添加成功', 'success')
    return redirect(url_for('users'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if session.get('username') != 'admin':
        flash('无权执行此操作', 'danger')
        return redirect(url_for('dashboard'))
    user = User.query.get(user_id)
    if user and user.username != 'admin':
        db.session.delete(user)
        db.session.commit()
        log_action('删除用户', f'管理员删除用户: {user.username}')
        flash('用户删除成功', 'success')
    else:
        flash('无法删除管理员用户', 'danger')
    return redirect(url_for('users'))

@app.route('/logs')
@login_required
def logs():
    if session.get('username') != 'admin':
        flash('无权访问此页面', 'danger')
        return redirect(url_for('dashboard'))
    logs = SystemLog.query.order_by(SystemLog.created_at.desc()).all()
    return render_template('logs.html', username=session.get('username'), logs=logs)

@app.route('/export_pdf/<int:task_id>')
@login_required
def export_pdf(task_id):
    task = ScanTask.query.filter_by(id=task_id, user_id=session['user_id']).first_or_404()
    vulnerabilities = Vulnerability.query.filter_by(scan_task_id=task_id).all()
    ai_analyses = AiAnalysis.query.filter_by(scan_task_id=task_id).all()
    
    vuln_analysis_map = {}
    for i, vuln in enumerate(vulnerabilities):
        if i < len(ai_analyses):
            vuln_analysis_map[vuln.id] = {
                'analysis': ai_analyses[i].analysis_text,
                'risk_level': ai_analyses[i].risk_level,
                'attack_vector': ai_analyses[i].attack_vector,
                'recommendations': ai_analyses[i].recommendations.split('\n')
            }
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm
    )
    
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=20,
        textColor=colors.HexColor('#2c3e50'),
        spaceAfter=20,
        alignment=1
    )
    
    heading2_style = ParagraphStyle(
        'CustomHeading2',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#9b59b6'),
        spaceAfter=10,
        spaceBefore=15
    )
    
    heading3_style = ParagraphStyle(
        'CustomHeading3',
        parent=styles['Heading3'],
        fontSize=12,
        textColor=colors.HexColor('#34495e'),
        spaceAfter=8
    )
    
    heading4_style = ParagraphStyle(
        'CustomHeading4',
        parent=styles['Heading4'],
        fontSize=11,
        textColor=colors.HexColor('#667eea'),
        spaceAfter=6,
        spaceBefore=8
    )
    
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        spaceAfter=6
    )
    
    elements = []
    
    elements.append(Paragraph("漏洞扫描报告", title_style))
    elements.append(Spacer(1, 0.5*cm))
    
    elements.append(Paragraph("扫描任务详情", heading2_style))
    
    task_data = [
        ['目标URL', task.target_url],
        ['扫描状态', task.status],
        ['创建时间', task.created_at.strftime('%Y-%m-%d %H:%M:%S')],
        ['完成时间', task.completed_at.strftime('%Y-%m-%d %H:%M:%S') if task.completed_at else '-'],
        ['发现漏洞数', str(len(vulnerabilities))]
    ]
    
    task_table = Table(task_data, colWidths=[4*cm, 10*cm])
    task_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f5f7fa')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#2c3e50')),
        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
        ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#ddd')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(task_table)
    elements.append(Spacer(1, 0.5*cm))
    
    elements.append(Paragraph("漏洞检测结果", heading2_style))
    
    if vulnerabilities:
        for i, vuln in enumerate(vulnerabilities):
            if i > 0:
                elements.append(Spacer(1, 0.3*cm))
            
            severity_color = {
                'Critical': '#e74c3c',
                'High': '#e67e22',
                'Medium': '#f39c12',
                'Low': '#27ae60'
            }.get(vuln.severity, '#95a5a6')
            
            elements.append(Paragraph(f"{i+1}. {vuln.type} [{vuln.severity}]", heading3_style))
            
            vuln_data = [
                ['严重程度', vuln.severity],
                ['描述', vuln.description],
                ['检测时间', vuln.found_at.strftime('%Y-%m-%d %H:%M:%S')],
            ]
            
            if vuln.payload:
                vuln_data.append(['有效载荷', vuln.payload])
            
            vuln_table = Table(vuln_data, colWidths=[3*cm, 11*cm])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f5f7fa')),
                ('TEXTCOLOR', (0, 0), (0, 0), colors.HexColor(severity_color)),
                ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#2c3e50')),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('ALIGN', (1, 0), (1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#eee')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))
            elements.append(vuln_table)
            
            if vuln_analysis_map.get(vuln.id):
                analysis = vuln_analysis_map[vuln.id]
                elements.append(Spacer(1, 0.2*cm))
                elements.append(Paragraph(f"AI深度分析 [{analysis['risk_level']}]", heading4_style))
                elements.append(Paragraph(analysis['analysis'], normal_style))
                
                elements.append(Paragraph("攻击向量", heading4_style))
                elements.append(Paragraph(analysis['attack_vector'], normal_style))
                
                elements.append(Paragraph("修复建议", heading4_style))
                rec_data = [[f"{j+1}. {rec}"] for j, rec in enumerate(analysis['recommendations'])]
                rec_table = Table(rec_data, colWidths=[14*cm])
                rec_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('LEFTPADDING', (0, 0), (-1, -1), 5),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ]))
                elements.append(rec_table)
    else:
        elements.append(Paragraph("未发现漏洞 - 目标网站在本次扫描中未发现已知漏洞。", normal_style))
    
    elements.append(Spacer(1, 1*cm))
    elements.append(Paragraph(f"报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                               ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=colors.grey)))
    
    doc.build(elements)
    
    buffer.seek(0)
    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=scan_report_{task_id}.pdf'
    
    log_action('导出PDF报告', f'导出扫描任务 {task_id} 的PDF报告')
    
    return response

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=8080)
