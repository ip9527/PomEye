#!/bin/bash
# PomEye GUI 启动脚本（使用虚拟环境）

cd "$(dirname "$0")"

echo "═══════════════════════════════════════════════════════════"
echo "PomEye - Maven 项目依赖漏洞检测工具"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "启动参数：使用虚拟环境 venv"
echo ""

# 检查虚拟环境
if [ ! -f "./venv/bin/python3" ]; then
    echo "✗ 虚拟环境不存在: ./venv"
    echo "  正在创建虚拟环境..."
    echo ""
    
    # 创建虚拟环境
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo "✗ 创建虚拟环境失败！"
        echo "  请确保已安装 Python 3.8 或更高版本"
        exit 1
    fi
    
    echo "✓ 虚拟环境创建成功"
    echo ""
    
    # 激活虚拟环境并安装依赖
    echo "正在安装依赖包..."
    echo ""
    ./venv/bin/pip install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "✗ 安装依赖失败！"
        exit 1
    fi
    
    echo "✓ 依赖安装成功"
    echo ""
fi

echo "✓ 虚拟环境已就绪"
echo ""

# 启动 GUI
echo "启动 GUI..."
./venv/bin/python3 main.py

# GUI 退出后
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "程序已退出，虚拟环境自动关闭"
echo "═══════════════════════════════════════════════════════════"
