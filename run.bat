@echo off
REM PomEye GUI 启动脚本（Windows版）
chcp 65001 >nul
cd /d "%~dp0"

echo ═══════════════════════════════════════════════════════════
echo PomEye - Maven 项目依赖漏洞检测工具
echo ═══════════════════════════════════════════════════════════
echo.
echo 启动参数：使用虚拟环境 venv
echo.

REM 检查虚拟环境是否存在
if not exist "venv\Scripts\python.exe" (
    echo ✗ 虚拟环境不存在: venv
    echo   正在创建虚拟环境...
    echo.
    
    REM 创建虚拟环境
    python -m venv venv
    if errorlevel 1 (
        echo ✗ 创建虚拟环境失败！
        echo   请确保已安装 Python 3.8 或更高版本
        echo.
        pause
        exit /b 1
    )
    
    echo ✓ 虚拟环境创建成功
    echo.
    
    REM 激活虚拟环境并安装依赖
    echo 正在安装依赖包...
    echo.
    venv\Scripts\pip install -r requirements.txt
    if errorlevel 1 (
        echo ✗ 安装依赖失败！
        echo.
        pause
        exit /b 1
    )
    
    echo ✓ 依赖安装成功
    echo.
)

echo ✓ 虚拟环境已就绪
echo.

REM 启动 GUI
echo 启动 GUI...
echo.
venv\Scripts\python.exe main.py

REM GUI 退出后
echo.
echo ═══════════════════════════════════════════════════════════
echo 程序已退出，虚拟环境自动关闭
echo ═══════════════════════════════════════════════════════════
echo.

REM 如果程序异常退出，保持窗口打开以查看错误信息
if errorlevel 1 (
    echo.
    echo ═══════════════════════════════════════════════════════════
    echo 程序执行出错，请检查上面的错误信息
    echo ═══════════════════════════════════════════════════════════
    pause
)
