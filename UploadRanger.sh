#!/bin/bash
# UploadRanger Linux启动脚本

echo "=========================================="
echo "  UploadRanger"
echo "  文件上传漏洞测试工具"
echo "  by bae"
echo "=========================================="
echo ""

# 检查Python
if ! command -v python3 &> /dev/null; then
    echo "错误: 未找到Python3，请先安装Python3"
    exit 1
fi

# 检查依赖
python3 -c "import requests, bs4, PIL" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "正在安装依赖..."
    pip3 install -r requirements.txt
fi

# 启动程序
python3 main.py
