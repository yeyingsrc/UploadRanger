#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UploadRanger - 文件上传漏洞测试工具
作者: bae
版本: v1.0.0
"""

import sys
import os

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui.main_window import run_gui

if __name__ == "__main__":
    run_gui()
