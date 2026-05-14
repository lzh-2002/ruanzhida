@echo off
chcp 65001 >nul
title Windows安全加固 - 禁用SMBv1协议 & 封禁445端口
color 0A

:: ==============================================
:: 校验管理员权限（必须管理员运行，否则操作失败）
:: ==============================================
fltmc >nul 2>&1
if %errorlevel% neq 0 (
    echo 错误：请【右键以管理员身份】运行此脚本！
    echo.
    pause
    exit /b 1
)
echo 已获取管理员权限，开始执行安全加固...
echo.

:: ==============================================
:: 步骤1：彻底禁用SMBv1协议（客户端+服务端）
:: ==============================================
echo 正在禁用 SMBv1 服务端协议...
PowerShell -Command "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force" >nul 2>&1

echo 正在禁用 SMBv1 客户端协议...
PowerShell -Command "Set-SmbClientConfiguration -EnableSMB1Protocol $false -Force" >nul 2>&1

echo 正在卸载系统SMBv1功能组件...
dism /online /disable-feature /featurename:SMB1Protocol /norestart >nul 2>&1

:: ==============================================
:: 步骤2：防火墙双向封禁TCP 445端口（入站+出站）
:: ==============================================
echo 正在清理旧的445端口规则（避免重复）...
netsh advfirewall firewall delete rule name="Block TCP 445 Inbound" >nul 2>&1
netsh advfirewall firewall delete rule name="Block TCP 445 Outbound" >nul 2>&1

echo 正在封禁【入站】TCP 445端口...
netsh advfirewall firewall add rule name="Block TCP 445 Inbound" dir=in action=block protocol=TCP localport=445 profile=any enable=yes >nul

echo 正在封禁【出站】TCP 445端口...
netsh advfirewall firewall add rule name="Block TCP 445 Outbound" dir=out action=block protocol=TCP remoteport=445 profile=any enable=yes >nul

:: ==============================================
:: 执行完成提示
:: ==============================================
echo.
echo ==============================================
echo 操作执行完成！
echo ✅ SMBv1 协议已彻底禁用
echo ✅ TCP 445 端口已双向封禁
echo ℹ️ 建议：重启电脑使所有配置完全生效
echo ==============================================
echo.
pause
exit /b 0