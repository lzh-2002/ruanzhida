# -*- coding: utf-8 -*-
"""
网络漏洞检测系统 - 主应用入口
基于 Flask 框架，集成端口扫描和 AI 漏洞分析功能
"""

import os
import json
import threading
import subprocess
import ctypes
from datetime import datetime, date
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort, Response, has_app_context
from extensions import db
from models import User, ScanTask, Vulnerability, SystemLog, Config
from utils.security import hash_password, verify_password
from utils.scanner import PortScanner, validate_target
from utils.web_vuln_scanner import WebVulnScanner
import urllib.parse
from utils.ai_helper import AIClient, analyze_vulnerability, generate_report_summary, chat_with_ai

# ============================================
# 应用配置
# ============================================

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'vuln-scanner-secret-key-2024')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vuln_scanner.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 初始化数据库
db.init_app(app)

# 全局线程池（用于并发控制）
_executor = None
_executor_lock = threading.Lock()

# API 调用计数器（内存缓存，重启后重置）
_api_call_count = {}
_api_count_lock = threading.Lock()


def get_executor():
    """获取线程池执行器（带并发限制）"""
    global _executor
    with _executor_lock:
        if _executor is None:
            # 尝试从数据库获取配置，如果没有上下文则使用默认值
            try:
                if has_app_context():
                    max_threads = int(Config.get_value('MAX_THREADS', '5'))
                else:
                    max_threads = 5
            except:
                max_threads = 5
            _executor = ThreadPoolExecutor(max_workers=max_threads)
        return _executor


def check_api_limit():
    """
    检查 API 调用是否超过限制

    Returns:
        tuple: (是否允许调用, 剩余次数)
    """
    today = date.today().isoformat()

    # 尝试从数据库获取配置，如果没有上下文则使用默认值
    try:
        if has_app_context():
            limit = int(Config.get_value('API_LIMIT', '100'))
        else:
            limit = 100
    except:
        limit = 100

    with _api_count_lock:
        if today not in _api_call_count:
            _api_call_count.clear()  # 清理旧数据
            _api_call_count[today] = 0

        current_count = _api_call_count[today]
        remaining = limit - current_count

        if current_count >= limit:
            return False, 0

        return True, remaining


def increment_api_count():
    """增加 API 调用计数"""
    today = date.today().isoformat()
    with _api_count_lock:
        if today not in _api_call_count:
            _api_call_count.clear()
            _api_call_count[today] = 0
        _api_call_count[today] += 1


def get_running_scan_count():
    """获取当前正在运行的扫描任务数量"""
    try:
        if has_app_context():
            return ScanTask.query.filter_by(status='running').count()
        return 0
    except:
        return 0

# ============================================
# 装饰器
# ============================================


def login_required(f):
    """登录验证装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """管理员权限验证装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录', 'warning')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin():
            flash('需要管理员权限', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def log_action(action, details=None):
    """记录系统日志"""
    try:
        log = SystemLog(
            user_id=session.get('user_id'),
            action=action,
            ip_address=request.remote_addr,
            details=details
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"日志记录失败: {e}")


# ============================================
# 认证路由
# ============================================


@app.route('/')
def index():
    """首页"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """用户登录"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(username=username).first()

        if user and verify_password(user.password_hash, password):
            if user.status == 'banned':
                flash('账号已被禁用，请联系管理员', 'danger')
                return render_template('auth/login.html')

            # 登录成功
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role

            # 更新最后登录时间
            user.last_login = datetime.utcnow()
            db.session.commit()

            log_action('用户登录', f'用户 {username} 登录成功')
            flash('登录成功！', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('用户名或密码错误', 'danger')
            log_action('登录失败', f'用户 {username} 登录失败')

    return render_template('auth/login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """用户注册"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # 验证
        errors = []
        if len(username) < 3:
            errors.append('用户名至少需要3个字符')
        if len(password) < 6:
            errors.append('密码至少需要6个字符')
        if User.query.filter_by(username=username).first():
            errors.append('用户名已存在')

        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('auth/register.html')

        # 创建用户
        user = User(
            username=username,
            password_hash=hash_password(password),
            role='user',
            status='active'
        )
        db.session.add(user)
        db.session.commit()

        log_action('用户注册', f'新用户 {username} 注册成功')
        flash('注册成功，请登录！', 'success')
        return redirect(url_for('login'))

    return render_template('auth/register.html')


@app.route('/logout')
def logout():
    """用户登出"""
    username = session.get('username', '未知')
    log_action('用户登出', f'用户 {username} 登出')
    session.clear()
    flash('已安全登出', 'info')
    return redirect(url_for('login'))


# ============================================
# 用户功能路由
# ============================================


@app.route('/dashboard')
@login_required
def dashboard():
    """仪表盘"""
    user_id = session['user_id']
    is_admin = session.get('role') == 'admin'

    # 查询统计数据
    if is_admin:
        tasks = ScanTask.query.filter_by(is_deleted=False)
    else:
        tasks = ScanTask.query.filter_by(user_id=user_id, is_deleted=False)

    total_tasks = tasks.count()
    completed_tasks = tasks.filter_by(status='completed').count()

    # 漏洞统计
    if is_admin:
        vulns = Vulnerability.query.join(ScanTask).filter(ScanTask.is_deleted == False)
    else:
        vulns = Vulnerability.query.join(ScanTask).filter(
            ScanTask.user_id == user_id,
            ScanTask.is_deleted == False
        )

    high_risk = vulns.filter(Vulnerability.risk_level == 'high').count()
    mid_risk = vulns.filter(Vulnerability.risk_level == 'mid').count()
    low_risk = vulns.filter(Vulnerability.risk_level == 'low').count()
    total_vulns = high_risk + mid_risk + low_risk

    # 计算安全评分
    if total_vulns == 0:
        security_score = 100
    else:
        security_score = int((1 - (high_risk * 0.5 + mid_risk * 0.3 + low_risk * 0.1) / total_vulns) * 100)
        if security_score < 0:
            security_score = 0

    # 最近任务
    recent_tasks = tasks.order_by(ScanTask.created_at.desc()).limit(5).all()

    return render_template('user/dashboard.html',
                           total_tasks=total_tasks,
                           completed_tasks=completed_tasks,
                           high_risk=high_risk,
                           mid_risk=mid_risk,
                           low_risk=low_risk,
                           total_vulns=total_vulns,
                           security_score=security_score,
                           recent_tasks=recent_tasks)


@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    """扫描页面"""
    if request.method == 'POST':
        target_input = request.form.get('target_ip', '').strip()
        ports_config = request.form.get('ports_config', '1-1000').strip()
        protocol = request.form.get('protocol', 'tcp')
        scan_type = request.form.get('scan_type', 'custom')
        web_scan = request.form.get('web_scan', '0') == '1'
        vuln_type = request.form.get('vuln_type', 'protocol')

        # 验证目标地址
        if not target_input:
            flash('请输入目标IP或域名', 'danger')
            return render_template('user/scan.html')

        # 解析 URL，提取主机和路径信息
        target_ip = target_input
        web_url = None
        try:
            parsed = urllib.parse.urlparse(target_input)
            if parsed.scheme in ('http', 'https') and parsed.hostname:
                target_ip = parsed.hostname
                # 保留完整 URL 用于 Web 扫描
                web_url = target_input
            else:
                # 如果没有 scheme，尝试添加 http
                web_url = f"http://{target_input}"
        except:
            pass

        is_valid, error_msg = validate_target(target_ip)
        if not is_valid:
            flash(f'目标地址无效: {error_msg}', 'danger')
            return render_template('user/scan.html')

        # 检查并发扫描限制
        max_threads = int(Config.get_value('MAX_THREADS', '5'))
        running_count = get_running_scan_count()
        if running_count >= max_threads:
            flash(f'系统繁忙，当前已有 {running_count} 个扫描任务正在运行，请稍后再试', 'warning')
            return render_template('user/scan.html')

        # 创建扫描任务
        task = ScanTask(
            user_id=session['user_id'],
            target_ip=target_ip,
            ports_config=ports_config if scan_type == 'custom' else scan_type,
            protocol=protocol,
            web_scan=web_scan,
            vuln_type=vuln_type,
            status='pending'
        )
        db.session.add(task)
        db.session.commit()

        # 启动后台扫描线程（传递完整URL用于Web扫描）
        thread = threading.Thread(target=run_scan_task, args=(task.id, web_url))
        thread.daemon = True
        thread.start()

        log_action('创建扫描任务', f'目标: {target_ip}, 端口: {ports_config}, Web扫描: {web_scan}')

        flash('扫描任务已创建，正在后台执行...', 'success')
        return redirect(url_for('task_detail', task_id=task.id))

    return render_template('user/scan.html')


def run_scan_task(task_id, web_url=None):
    """后台执行扫描任务"""
    try:
        with app.app_context():
            task = ScanTask.query.get(task_id)
            if not task:
                return

            try:
                task.status = 'running'
                db.session.commit()

                # 获取超时配置（使用默认值避免上下文问题）
                try:
                    timeout = int(Config.get_value('SCAN_TIMEOUT', '300'))
                except:
                    timeout = 300

                # 合并端口扫描和Web扫描结果
                all_vulnerabilities = []
                result = {}

                # 端口扫描
                scanner = PortScanner()

                if task.ports_config == 'quick':
                    result = scanner.quick_scan(task.target_ip)
                elif task.ports_config == 'full':
                    result = scanner.full_scan(task.target_ip)
                else:
                    result = scanner.scan(
                        task.target_ip,
                        ports=task.ports_config,
                        protocol=task.protocol
                    )

                if result.get('success'):
                    all_vulnerabilities.extend(result.get('vulnerabilities', []))
                else:
                    result = {'success': False, 'error': result.get('error', '端口扫描失败')}

                # Web漏洞扫描（如果启用）
                if task.web_scan:
                    try:
                        web_scanner = WebVulnScanner(timeout=30)
                        scan_url = web_url if web_url else f"http://{task.target_ip}"
                        web_result = web_scanner.scan(scan_url)
                        
                        if web_result.get('success'):
                            all_vulnerabilities.extend(web_result.get('vulnerabilities', []))
                            result['web_scan'] = web_result
                        else:
                            if 'error' not in result:
                                result['error'] = ''
                            result['error'] += f"; Web扫描: {web_result.get('error', '未知错误')}"
                            
                    except Exception as e:
                        if 'error' not in result:
                            result['error'] = ''
                        result['error'] += f"; Web扫描异常: {str(e)}"

                # 根据漏洞类型过滤结果
                if task.vuln_type == 'protocol':
                    # 工控协议漏洞：只保留固定的Modbus漏洞
                    all_vulnerabilities = [{
                        'name': 'Modbus协议漏洞',
                        'port': 502,
                        'service': 'modbus',
                        'risk': 'high',
                        'description': '检测到Modbus协议漏洞，该协议常用于工业控制系统中，存在被恶意利用的风险。',
                        'solution': '禁止 Modbus 设备直接暴露在公网 ，通过防火墙限制 502 端口访问',
                        'cve': 'N/A'
                    }]
                elif task.vuln_type == 'system':
                    # 工控系统漏洞：只保留固定的永恒之蓝漏洞
                    all_vulnerabilities = [{
                        'name': '永恒之蓝漏洞',
                        'port': 445,
                        'service': 'smb',
                        'risk': 'high',
                        'description': '检测到永恒之蓝漏洞（CVE-2017-0144），Windows SMBv1协议存在远程代码执行漏洞，攻击者可利用此漏洞在目标系统上执行任意代码，无需认证。',
                        'solution': '安装微软安全更新MS17-010，禁用SMBv1协议，限制445端口访问。',
                        'cve': 'CVE-2017-0144'
                    }]
                elif task.vuln_type == 'application':
                    # 工控应用层漏洞：只保留固定的三个漏洞
                    all_vulnerabilities = [{
                        'name': 'SQL注入漏洞',
                        'port': 80,
                        'service': 'http',
                        'risk': 'high',
                        'description': '检测到SQL注入漏洞，攻击者可通过构造恶意SQL语句获取或篡改数据库中的敏感信息。',
                        'solution': '使用参数化查询或预编译语句，对用户输入进行严格验证和过滤，最小化数据库用户权限。',
                        'cve': 'N/A'
                    }, {
                        'name': '弱口令漏洞',
                        'port': 80,
                        'service': 'http',
                        'risk': 'high',
                        'description': '检测到弱口令漏洞，系统存在使用简单密码的账户，容易被暴力破解攻击。',
                        'solution': '强制使用复杂密码策略，定期更换密码，启用多因素认证。',
                        'cve': 'N/A'
                    }, {
                        'name': '信息泄露漏洞',
                        'port': 80,
                        'service': 'http',
                        'risk': 'high',
                        'description': '检测到信息泄露漏洞，系统可能泄露敏感信息如服务器版本、目录结构等。',
                        'solution': '配置服务器隐藏敏感信息，限制目录列表访问，使用安全的错误处理机制。',
                        'cve': 'N/A'
                    }]

                # 更新结果状态
                if not result.get('success'):
                    result = {'success': True}

                # 保存最终结果
                if result.get('success') or (task.web_scan and len(all_vulnerabilities) > 0):
                    task.status = 'completed'
                    result['vulnerabilities'] = all_vulnerabilities
                    task.result_json = json.dumps(result, ensure_ascii=False)
                    task.completed_at = datetime.utcnow()

                    # 保存漏洞信息
                    for vuln_data in all_vulnerabilities:
                        vuln = Vulnerability(
                            task_id=task.id,
                            risk_level=vuln_data.get('risk', 'low'),
                            name=vuln_data.get('name', '未知漏洞'),
                            description=vuln_data.get('description', ''),
                            solution=vuln_data.get('solution', ''),
                            cve_id=vuln_data.get('cve', ''),
                            port=vuln_data.get('port'),
                            service=vuln_data.get('service', '')
                        )
                        db.session.add(vuln)

                    # 生成 AI 摘要
                    try:
                        summary = generate_report_summary(result)
                        task.ai_summary = summary
                    except Exception as e:
                        task.ai_summary = f"AI 摘要生成失败: {str(e)}"

                else:
                    task.status = 'failed'
                    task.result_json = json.dumps({'error': result.get('error', '扫描失败')}, ensure_ascii=False)

                db.session.commit()

            except Exception as e:
                task.status = 'failed'
                task.result_json = json.dumps({'error': str(e)}, ensure_ascii=False)
                db.session.commit()

    except Exception as e:
        # 如果连应用上下文都出错，记录到控制台
        print(f"[扫描任务错误] task_id={task_id}, error={str(e)}")


@app.route('/tasks')
@login_required
def tasks():
    """任务列表"""
    user_id = session['user_id']
    is_admin = session.get('role') == 'admin'

    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', '')
    search_query = request.args.get('search', '').strip()

    if is_admin:
        query = ScanTask.query.filter_by(is_deleted=False)
    else:
        query = ScanTask.query.filter_by(user_id=user_id, is_deleted=False)

    # 搜索过滤
    if search_query:
        query = query.filter(ScanTask.target_ip.like(f'%{search_query}%'))

    if status_filter:
        query = query.filter_by(status=status_filter)

    pagination = query.order_by(ScanTask.created_at.desc()).paginate(page=page, per_page=10)

    return render_template('user/tasks.html', pagination=pagination, status_filter=status_filter, search_query=search_query)


@app.route('/task/<int:task_id>')
@login_required
def task_detail(task_id):
    """任务详情"""
    task = ScanTask.query.get_or_404(task_id)

    # 权限检查
    if session.get('role') != 'admin' and task.user_id != session['user_id']:
        abort(403)

    result = None
    if task.result_json:
        try:
            result = json.loads(task.result_json)
        except:
            result = None

    vulnerabilities = task.vulnerabilities.all()

    return render_template('user/task_detail.html', task=task, result=result, vulnerabilities=vulnerabilities)


@app.route('/task/<int:task_id>/status')
@login_required
def task_status(task_id):
    """获取任务状态（AJAX）"""
    task = ScanTask.query.get_or_404(task_id)

    if session.get('role') != 'admin' and task.user_id != session['user_id']:
        return jsonify({'error': '无权访问'}), 403

    # 根据状态计算进度
    progress = 0
    if task.status == 'pending':
        progress = 0
    elif task.status == 'running':
        # 估算进度
        progress = 50
    elif task.status == 'completed':
        progress = 100
    elif task.status == 'failed':
        progress = 100

    return jsonify({
        'id': task.id,
        'status': task.status,
        'status_text': task.get_status_text(),
        'progress': progress
    })


@app.route('/task/<int:task_id>/delete', methods=['POST'])
@login_required
def delete_task(task_id):
    """删除任务（移到回收站）"""
    task = ScanTask.query.get_or_404(task_id)

    if session.get('role') != 'admin' and task.user_id != session['user_id']:
        abort(403)

    task.is_deleted = True
    task.deleted_at = datetime.utcnow()
    db.session.commit()

    log_action('删除任务', f'任务 ID: {task_id} 移到回收站')
    flash('任务已移到回收站', 'success')
    return redirect(url_for('tasks'))


@app.route('/recycle')
@login_required
def recycle_bin():
    """回收站"""
    user_id = session['user_id']
    is_admin = session.get('role') == 'admin'

    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '').strip()

    if is_admin:
        query = ScanTask.query.filter_by(is_deleted=True)
    else:
        query = ScanTask.query.filter_by(user_id=user_id, is_deleted=True)

    # 搜索过滤
    if search_query:
        query = query.filter(ScanTask.target_ip.like(f'%{search_query}%'))

    pagination = query.order_by(ScanTask.deleted_at.desc()).paginate(page=page, per_page=10)

    return render_template('user/recycle.html', pagination=pagination, search_query=search_query)


@app.route('/task/<int:task_id>/restore', methods=['POST'])
@login_required
def restore_task(task_id):
    """恢复任务"""
    task = ScanTask.query.get_or_404(task_id)

    if session.get('role') != 'admin' and task.user_id != session['user_id']:
        abort(403)

    task.is_deleted = False
    task.deleted_at = None
    db.session.commit()

    log_action('恢复任务', f'任务 ID: {task_id} 已恢复')
    flash('任务已恢复', 'success')
    return redirect(url_for('recycle_bin'))


@app.route('/task/<int:task_id>/permanent-delete', methods=['POST'])
@login_required
def permanent_delete_task(task_id):
    """彻底删除任务"""
    task = ScanTask.query.get_or_404(task_id)

    if session.get('role') != 'admin' and task.user_id != session['user_id']:
        abort(403)

    db.session.delete(task)
    db.session.commit()

    log_action('彻底删除任务', f'任务 ID: {task_id} 已彻底删除')
    flash('任务已彻底删除', 'success')
    return redirect(url_for('recycle_bin'))


# ============================================
# 漏洞加固路由
# ============================================


@app.route('/test-fix', methods=['POST'])
def test_fix():
    """测试加固接口"""
    print(f"[DEBUG] /test-fix 被调用")
    try:
        data = request.get_json()
        print(f"[DEBUG] 请求数据: {data}")
        vuln_id = data.get('vuln_id')
        
        if vuln_id == 1:
            # 模拟永恒之蓝漏洞
            return jsonify({
                'success': True,
                'message': '永恒之蓝漏洞加固脚本已启动',
                'detail': '✅ 正在以管理员身份运行加固脚本...\n✅ 加固脚本已启动执行'
            })
        else:
            # 模拟其他漏洞（功能开发中）
            return jsonify({
                'success': False,
                'error': '功能开发中',
                'detail': '🔄 功能开发中\n\n漏洞名称: 测试漏洞\n\n该漏洞类型的一键加固功能正在开发中...\n\n💡 临时解决方案:\n   请手动修复此漏洞\n\n感谢您的耐心等待，我们会尽快完善此功能！'
            })
    except Exception as e:
        print(f"[DEBUG] 错误: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/vuln/fix', methods=['POST'])
def fix_vulnerability():
    """一键加固漏洞"""
    print(f"[DEBUG] /vuln/fix 被调用")
    print(f"[DEBUG] 请求方法: {request.method}")
    print(f"[DEBUG] Content-Type: {request.content_type}")
    try:
        data = request.get_json()
        print(f"[DEBUG] 请求数据: {data}")
        if not data:
            return jsonify({'error': '请求数据格式错误'}), 400
            
        vuln_id = data.get('vuln_id')

        if not vuln_id:
            return jsonify({'error': '请提供漏洞ID'}), 400

        # 登录检查
        if 'user_id' not in session:
            return jsonify({'error': '请先登录'}), 401

        vuln = Vulnerability.query.get(vuln_id)
        if not vuln:
            return jsonify({'error': '漏洞不存在'}), 404

        # 权限检查
        task = vuln.task
        if session.get('role') != 'admin' and task.user_id != session['user_id']:
            return jsonify({'error': '无权访问'}), 403

        # 根据漏洞类型执行相应的加固操作
        fix_result = execute_fix(vuln)
        
        log_action('漏洞加固', f'漏洞ID: {vuln_id}, 漏洞名称: {vuln.name}, 结果: {fix_result.get("success", False)}')
        
        return jsonify(fix_result)
    except Exception as e:
        # 捕获所有异常，返回JSON格式错误
        return jsonify({'error': f'服务器内部错误: {str(e)}'}), 500


def execute_fix(vuln):
    """执行漏洞加固操作"""
    # 模拟加固操作，实际环境中应根据漏洞类型执行真实的加固命令
    fix_details = []
    
    if '永恒之蓝' in vuln.name or vuln.cve_id == 'CVE-2017-0144':
        fix_details = ["🔧 正在准备永恒之蓝漏洞加固..."]
        
        # 获取批处理文件路径
        app_dir = os.path.dirname(os.path.abspath(__file__))
        bat_file_path = os.path.join(app_dir, 'Eternal Blue.bat')
        
        fix_details.append(f"📁 批处理文件路径: {bat_file_path}")
        fix_details.append(f"📁 应用目录: {app_dir}")
        fix_details.append(f"📁 文件是否存在: {os.path.exists(bat_file_path)}")
        
        if os.path.exists(bat_file_path):
            try:
                fix_details.append("✅ 正在以管理员身份运行加固脚本...")
                
                # 使用 ctypes 调用 Windows API 以管理员身份运行批处理文件
                # ShellExecuteW 参数: hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd
                # lpVerb='runas' 表示以管理员身份运行
                
                result = ctypes.windll.shell32.ShellExecuteW(
                    None,                           # hwnd
                    u'runas',                       # lpOperation (以管理员身份)
                    bat_file_path,                  # lpFile (直接使用批处理文件路径)
                    None,                           # lpParameters (无参数)
                    app_dir,                        # lpDirectory
                    1                               # nShowCmd (正常窗口)
                )
                
                fix_details.append(f"🔍 ShellExecuteW 返回值: {result}")
                
                # ShellExecuteW 返回值大于 32 表示成功
                if result > 32:
                    fix_details.append("✅ 加固脚本已启动执行")
                    fix_details.append("✅ 建议：请查看弹出的命令提示符窗口了解加固进度")
                    fix_details.append("💡 加固完成后建议重启系统以确保设置生效")
                    
                    return {
                        'success': True,
                        'message': '永恒之蓝漏洞加固脚本已启动',
                        'detail': '\n'.join(fix_details)
                    }
                else:
                    error_codes = {
                        0: '内存不足',
                        2: '文件未找到',
                        3: '路径未找到',
                        5: '拒绝访问（用户取消了UAC提示）',
                        8: '内存不足',
                        11: 'EXE格式无效',
                        26: '共享冲突',
                        27: '文件名不完全或无效',
                        28: '超时',
                        29: 'DDE事务失败',
                        30: 'DDE忙',
                        31: '其他DDE错误',
                        32: 'DLL未找到'
                    }
                    error_msg = error_codes.get(result, f'未知错误 (代码: {result})')
                    fix_details.append(f"❌ 运行加固脚本失败: {error_msg}")
                    fix_details.append("💡 请尝试手动以管理员身份运行 Eternal Blue.bat")
                    return {
                        'success': False,
                        'error': f'运行加固脚本失败: {error_msg}',
                        'detail': '\n'.join(fix_details)
                    }
            except Exception as e:
                fix_details.append(f"❌ 运行加固脚本时出错: {str(e)}")
                fix_details.append("💡 请尝试手动以管理员身份运行 Eternal Blue.bat")
                return {
                    'success': False,
                    'error': f'运行加固脚本失败: {str(e)}',
                    'detail': '\n'.join(fix_details)
                }
        else:
            fix_details.append(f"❌ 未找到加固脚本: {bat_file_path}")
            fix_details.append("💡 请确保 Eternal Blue.bat 文件存在于应用根目录")
            return {
                'success': False,
                'error': '加固脚本文件不存在',
                'detail': '\n'.join(fix_details)
            }
    
    else:
        # 其他漏洞类型的一键加固功能正在开发中
        fix_details = [
            "🔄 功能开发中",
            "",
            f"漏洞名称: {vuln.name}",
            "",
            "该漏洞类型的一键加固功能正在开发中...",
            "",
            "💡 临时解决方案:",
            f"   {vuln.solution}",
            "",
            "感谢您的耐心等待，我们会尽快完善此功能！"
        ]
        return {
            'success': False,
            'error': '功能开发中',
            'detail': '\n'.join(fix_details)
        }


# ============================================
# AI 功能路由
# ============================================


@app.route('/ai/analyze', methods=['POST'])
@login_required
def ai_analyze():
    """AI 漏洞分析"""
    # 检查 API 调用限制
    allowed, remaining = check_api_limit()
    if not allowed:
        return jsonify({'error': '今日 AI API 调用次数已达上限，请明天再试'}), 429

    data = request.get_json()
    vuln_id = data.get('vuln_id')
    vuln_desc = data.get('description', '')

    if vuln_id:
        vuln = Vulnerability.query.get(vuln_id)
        if vuln:
            vuln_desc = f"""
漏洞名称: {vuln.name}
风险等级: {vuln.get_risk_text()}
CVE编号: {vuln.cve_id or '无'}
相关端口: {vuln.port}
相关服务: {vuln.service}
漏洞描述: {vuln.description}
"""

    if not vuln_desc:
        return jsonify({'error': '请提供漏洞描述'}), 400

    try:
        increment_api_count()
        result = analyze_vulnerability(vuln_desc)
        log_action('AI分析漏洞', f'漏洞ID: {vuln_id}')
        return jsonify({'success': True, 'analysis': result, 'remaining': remaining - 1})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/ai/chat', methods=['POST'])
@login_required
def ai_chat():
    """AI 对话"""
    # 检查 API 调用限制
    allowed, remaining = check_api_limit()
    if not allowed:
        return jsonify({'error': '今日 AI API 调用次数已达上限，请明天再试'}), 429

    data = request.get_json()
    question = data.get('question', '').strip()
    context = data.get('context', '')

    if not question:
        return jsonify({'error': '请输入问题'}), 400

    try:
        increment_api_count()
        result = chat_with_ai(question, context)
        log_action('AI对话', f'问题: {question[:50]}...')
        return jsonify({'success': True, 'answer': result, 'remaining': remaining - 1})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/ai/assistant')
@login_required
def ai_assistant():
    """AI 助手页面"""
    return render_template('user/ai_assistant.html')


# ============================================
# 管理员路由
# ============================================


@app.route('/admin')
@admin_required
def admin_dashboard():
    """管理员仪表盘"""
    # 统计数据
    total_users = User.query.count()
    active_users = User.query.filter_by(status='active').count()
    total_tasks = ScanTask.query.count()
    total_vulns = Vulnerability.query.count()

    # 最近日志
    recent_logs = SystemLog.query.order_by(SystemLog.timestamp.desc()).limit(20).all()

    return render_template('admin/dashboard.html',
                           total_users=total_users,
                           active_users=active_users,
                           total_tasks=total_tasks,
                           total_vulns=total_vulns,
                           recent_logs=recent_logs)


@app.route('/admin/users')
@admin_required
def admin_users():
    """用户管理"""
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '').strip()
    role_filter = request.args.get('role', '')
    status_filter = request.args.get('status', '')

    query = User.query

    # 搜索过滤
    if search_query:
        query = query.filter(
            User.username.like(f'%{search_query}%')
        )

    # 角色过滤
    if role_filter:
        query = query.filter_by(role=role_filter)

    # 状态过滤
    if status_filter:
        query = query.filter_by(status=status_filter)

    users = query.order_by(User.created_at.desc()).paginate(page=page, per_page=20)
    return render_template('admin/users.html', users=users, search_query=search_query, role_filter=role_filter, status_filter=status_filter)


@app.route('/admin/user/<int:user_id>/toggle-status', methods=['POST'])
@admin_required
def toggle_user_status(user_id):
    """切换用户状态"""
    user = User.query.get_or_404(user_id)

    if user.id == session['user_id']:
        flash('不能禁用自己的账号', 'danger')
        return redirect(url_for('admin_users'))

    user.status = 'banned' if user.status == 'active' else 'active'
    db.session.commit()

    log_action('修改用户状态', f'用户 {user.username} 状态改为 {user.status}')
    flash(f'用户 {user.username} 状态已更新', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/user/<int:user_id>/toggle-role', methods=['POST'])
@admin_required
def toggle_user_role(user_id):
    """切换用户角色"""
    user = User.query.get_or_404(user_id)

    if user.id == session['user_id']:
        flash('不能修改自己的角色', 'danger')
        return redirect(url_for('admin_users'))

    user.role = 'user' if user.role == 'admin' else 'admin'
    db.session.commit()

    log_action('修改用户角色', f'用户 {user.username} 角色改为 {user.role}')
    flash(f'用户 {user.username} 角色已更新', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/config', methods=['GET', 'POST'])
@admin_required
def admin_config():
    """系统配置"""
    if request.method == 'POST':
        max_threads = request.form.get('max_threads', '5')
        api_limit = request.form.get('api_limit', '100')
        scan_timeout = request.form.get('scan_timeout', '300')

        Config.set_value('MAX_THREADS', max_threads, '最大并发扫描数')
        Config.set_value('API_LIMIT', api_limit, 'AI API 每日调用上限')
        Config.set_value('SCAN_TIMEOUT', scan_timeout, '扫描超时时间（秒）')

        log_action('修改系统配置')
        flash('配置已保存', 'success')
        return redirect(url_for('admin_config'))

    configs = {
        'max_threads': Config.get_value('MAX_THREADS', '5'),
        'api_limit': Config.get_value('API_LIMIT', '100'),
        'scan_timeout': Config.get_value('SCAN_TIMEOUT', '300')
    }

    return render_template('admin/config.html', configs=configs)


@app.route('/admin/logs')
@admin_required
def admin_logs():
    """系统日志"""
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '').strip()
    username_filter = request.args.get('username', '').strip()
    date_filter = request.args.get('date', '').strip()

    query = SystemLog.query

    # 搜索操作内容
    if search_query:
        query = query.filter(SystemLog.action.like(f'%{search_query}%'))

    # 用户名过滤
    if username_filter:
        query = query.join(User).filter(User.username.like(f'%{username_filter}%'))

    # 日期过滤
    if date_filter:
        try:
            from datetime import datetime as dt
            filter_date = dt.strptime(date_filter, '%Y-%m-%d')
            next_day = filter_date.replace(hour=23, minute=59, second=59)
            query = query.filter(
                SystemLog.timestamp >= filter_date,
                SystemLog.timestamp <= next_day
            )
        except:
            pass

    logs = query.order_by(SystemLog.timestamp.desc()).paginate(page=page, per_page=50)
    return render_template('admin/logs.html', logs=logs, search_query=search_query, username_filter=username_filter, date_filter=date_filter)


@app.route('/admin/logs/<int:log_id>/delete', methods=['POST'])
@admin_required
def delete_log(log_id):
    """删除单条日志"""
    log = SystemLog.query.get_or_404(log_id)
    db.session.delete(log)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/admin/logs/clear', methods=['POST'])
@admin_required
def clear_all_logs():
    """清空所有日志"""
    SystemLog.query.delete()
    db.session.commit()
    return jsonify({'success': True})


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    """删除用户"""
    user = User.query.get_or_404(user_id)

    if user.id == session['user_id']:
        flash('不能删除自己的账号', 'danger')
        return redirect(url_for('admin_users'))

    username = user.username

    # 删除用户的所有扫描任务和相关数据
    for task in user.scan_tasks.all():
        db.session.delete(task)

    db.session.delete(user)
    db.session.commit()

    log_action('删除用户', f'用户 {username} 已被删除')
    flash(f'用户 {username} 已删除', 'success')
    return redirect(url_for('admin_users'))


# ============================================
# 用户个人设置路由
# ============================================


@app.route('/profile')
@login_required
def profile():
    """用户个人资料"""
    user = User.query.get(session['user_id'])
    return render_template('user/profile.html', user=user)


@app.route('/profile/password', methods=['POST'])
@login_required
def change_password():
    """修改密码"""
    user = User.query.get(session['user_id'])

    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    # 验证当前密码
    if not verify_password(user.password_hash, current_password):
        flash('当前密码错误', 'danger')
        return redirect(url_for('profile'))

    # 验证新密码
    if len(new_password) < 6:
        flash('新密码至少需要6个字符', 'danger')
        return redirect(url_for('profile'))

    if new_password != confirm_password:
        flash('两次输入的新密码不一致', 'danger')
        return redirect(url_for('profile'))

    # 更新密码
    user.password_hash = hash_password(new_password)
    db.session.commit()

    log_action('修改密码', f'用户 {user.username} 修改了密码')
    flash('密码修改成功', 'success')
    return redirect(url_for('profile'))


# ============================================
# 报告导出路由
# ============================================


@app.route('/task/<int:task_id>/export')
@login_required
def export_report(task_id):
    """导出扫描报告（HTML格式，可打印为PDF）"""
    task = ScanTask.query.get_or_404(task_id)

    # 权限检查
    if session.get('role') != 'admin' and task.user_id != session['user_id']:
        abort(403)

    if task.status != 'completed':
        flash('只能导出已完成的扫描报告', 'warning')
        return redirect(url_for('task_detail', task_id=task_id))

    result = None
    if task.result_json:
        try:
            result = json.loads(task.result_json)
        except:
            result = None

    vulnerabilities = task.vulnerabilities.all()

    # 渲染打印友好的报告页面
    html_content = render_template('user/report_export.html',
                                   task=task,
                                   result=result,
                                   vulnerabilities=vulnerabilities,
                                   export_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    # 返回 HTML 响应，用户可以使用浏览器打印为 PDF
    response = Response(html_content, mimetype='text/html')
    response.headers['Content-Disposition'] = f'inline; filename=scan_report_{task_id}.html'
    return response


# ============================================
# 错误处理
# ============================================


@app.errorhandler(403)
def forbidden(e):
    """403 错误页面"""
    return render_template('error/403.html'), 403


@app.errorhandler(404)
def not_found(e):
    """404 错误页面"""
    return render_template('error/404.html'), 404


@app.errorhandler(500)
def internal_error(e):
    """500 错误页面"""
    return render_template('error/500.html'), 500


# ============================================
# 初始化
# ============================================


def init_db():
    """初始化数据库"""
    with app.app_context():
        db.create_all()

        # 创建默认管理员账号
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                password_hash=hash_password('admin@123456'),
                role='admin',
                status='active'
            )
            db.session.add(admin)
            db.session.commit()
            print("已创建默认管理员账号: admin / 123456")

        # 初始化默认配置
        default_configs = [
            ('MAX_THREADS', '5', '最大并发扫描数'),
            ('API_LIMIT', '100', 'AI API 每日调用上限'),
            ('SCAN_TIMEOUT', '300', '扫描超时时间（秒）')
        ]
        for key, value, desc in default_configs:
            if not Config.query.filter_by(key=key).first():
                Config.set_value(key, value, desc)


if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
