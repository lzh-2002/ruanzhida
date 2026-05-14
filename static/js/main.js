/**
 * 网络漏洞检测系统 - 公共 JavaScript
 * 包含通用工具函数和页面交互逻辑
 */

// ========================================
// 工具函数
// ========================================

/**
 * 显示提示消息
 * @param {string} message - 消息内容
 * @param {string} type - 消息类型 (success/danger/warning/info)
 */
function showAlert(message, type = 'info') {
    const alertContainer = document.getElementById('alertContainer') || createAlertContainer();

    const alertHtml = `
        <div class="alert alert-${type} alert-dismissible fade show" role="alert">
            <i class="bi bi-${type === 'success' ? 'check-circle' : type === 'danger' ? 'exclamation-circle' : 'info-circle'} me-2"></i>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;

    alertContainer.insertAdjacentHTML('beforeend', alertHtml);

    // 5秒后自动关闭
    setTimeout(() => {
        const alerts = alertContainer.querySelectorAll('.alert');
        if (alerts.length > 0) {
            new bootstrap.Alert(alerts[0]).close();
        }
    }, 5000);
}

/**
 * 创建提示消息容器
 */
function createAlertContainer() {
    const container = document.createElement('div');
    container.id = 'alertContainer';
    container.style.cssText = 'position: fixed; top: 80px; right: 20px; z-index: 9999; max-width: 400px;';
    document.body.appendChild(container);
    return container;
}

/**
 * 格式化日期时间
 * @param {string|Date} date - 日期
 * @returns {string} 格式化后的日期字符串
 */
function formatDateTime(date) {
    const d = new Date(date);
    return d.toLocaleString('zh-CN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

/**
 * 复制文本到剪贴板
 * @param {string} text - 要复制的文本
 */
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        showAlert('已复制到剪贴板', 'success');
    } catch (err) {
        showAlert('复制失败', 'danger');
    }
}

/**
 * 确认对话框
 * @param {string} message - 确认消息
 * @returns {Promise<boolean>}
 */
function confirmAction(message) {
    return new Promise((resolve) => {
        if (confirm(message)) {
            resolve(true);
        } else {
            resolve(false);
        }
    });
}

// ========================================
// AJAX 请求封装
// ========================================

/**
 * 发送 AJAX 请求
 * @param {string} url - 请求 URL
 * @param {Object} options - 请求选项
 * @returns {Promise<Object>}
 */
async function ajax(url, options = {}) {
    const defaultOptions = {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json'
        }
    };

    const mergedOptions = { ...defaultOptions, ...options };

    if (mergedOptions.body && typeof mergedOptions.body === 'object') {
        mergedOptions.body = JSON.stringify(mergedOptions.body);
    }

    try {
        const response = await fetch(url, mergedOptions);
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || '请求失败');
        }

        return data;
    } catch (error) {
        console.error('AJAX Error:', error);
        throw error;
    }
}

// ========================================
// 页面加载完成后执行
// ========================================

document.addEventListener('DOMContentLoaded', function() {
    // 为所有具有 data-confirm 属性的表单添加确认提示
    document.querySelectorAll('form[data-confirm]').forEach(form => {
        form.addEventListener('submit', function(e) {
            const message = this.getAttribute('data-confirm');
            if (!confirm(message)) {
                e.preventDefault();
            }
        });
    });

    // 为所有具有 data-loading 属性的按钮添加加载状态
    document.querySelectorAll('button[data-loading]').forEach(button => {
        button.addEventListener('click', function() {
            const loadingText = this.getAttribute('data-loading');
            const originalText = this.innerHTML;

            this.disabled = true;
            this.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span>${loadingText}`;

            // 5秒后恢复（防止卡死）
            setTimeout(() => {
                this.disabled = false;
                this.innerHTML = originalText;
            }, 5000);
        });
    });

    // 工具提示初始化
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    tooltipTriggerList.forEach(el => new bootstrap.Tooltip(el));

    console.log('网络漏洞检测系统已加载');
});
