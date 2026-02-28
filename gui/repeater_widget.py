#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Repeater模块 - Burp风格的重放器
支持多标签、历史记录、请求编辑
"""

import httpx
import asyncio
from typing import List, Dict
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit,
    QPushButton, QComboBox, QLabel, QTabWidget, QSplitter,
    QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox,
    QPlainTextEdit, QApplication, QMenu, QInputDialog
)
from PySide6.QtCore import Qt, Signal, QThread
from PySide6.QtGui import QColor, QFont, QAction, QTextCursor

from .themes.dark_theme import COLORS
from .syntax_highlighter import HTTPHighlighter


class RepeaterWorker(QThread):
    """Repeater异步工作线程"""
    
    finished = Signal(dict)
    error = Signal(str)
    
    def __init__(self, request_data: dict):
        super().__init__()
        self.request_data = request_data
    
    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self._send_request())
            self.finished.emit(result)
            loop.close()
        except Exception as e:
            self.error.emit(str(e))
    
    async def _send_request(self):
        url = self.request_data.get('url', '')
        method = self.request_data.get('method', 'GET')
        headers = self.request_data.get('headers', {})
        body = self.request_data.get('body', '')
        
        # 确保URL有协议
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # 移除Content-Length头，让httpx自动计算
        headers.pop('Content-Length', None)
        headers.pop('content-length', None)
        
        async with httpx.AsyncClient(verify=False, timeout=30, follow_redirects=True) as client:
            if method == 'GET':
                response = await client.get(url, headers=headers)
            elif method == 'POST':
                response = await client.post(url, headers=headers, content=body.encode('utf-8') if body else None)
            elif method == 'PUT':
                response = await client.put(url, headers=headers, content=body.encode('utf-8') if body else None)
            elif method == 'DELETE':
                response = await client.delete(url, headers=headers)
            elif method == 'PATCH':
                response = await client.patch(url, headers=headers, content=body.encode('utf-8') if body else None)
            else:
                response = await client.request(method, url, headers=headers, content=body.encode('utf-8') if body else None)
            
            res_headers = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
            
            return {
                'status_code': response.status_code,
                'headers': res_headers,
                'body': response.text,
                'url': str(response.url)
            }


class RepeaterTab(QWidget):
    """单个Repeater标签页"""
    
    request_sent = Signal(dict, str)  # 请求数据, 标签名
    
    def __init__(self, tab_name: str = "Repeater"):
        super().__init__()
        self.tab_name = tab_name
        self.worker = None
        self.history = []  # 请求历史
        self.history_index = -1
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        # 控制栏
        control_layout = QHBoxLayout()
        
        control_layout.addWidget(QLabel("目标URL:"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("http://example.com/upload.php")
        control_layout.addWidget(self.url_input)
        
        control_layout.addWidget(QLabel("方法:"))
        self.method_combo = QComboBox()
        self.method_combo.addItems(["POST", "GET", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
        control_layout.addWidget(self.method_combo)
        
        # 历史导航按钮
        self.prev_btn = QPushButton("< 上一个")
        self.prev_btn.setEnabled(False)
        self.prev_btn.clicked.connect(self._go_prev)
        control_layout.addWidget(self.prev_btn)
        
        self.next_btn = QPushButton("下一个 >")
        self.next_btn.setEnabled(False)
        self.next_btn.clicked.connect(self._go_next)
        control_layout.addWidget(self.next_btn)
        
        self.send_btn = QPushButton("发送")
        self.send_btn.setObjectName("success")
        self.send_btn.setFixedWidth(80)
        self.send_btn.clicked.connect(self._send_request)
        control_layout.addWidget(self.send_btn)
        
        layout.addLayout(control_layout)
        
        # 分割器 - 请求和响应
        splitter = QSplitter(Qt.Vertical)
        
        # 请求编辑区
        req_group = QGroupBox("请求 (可编辑)")
        req_layout = QVBoxLayout(req_group)
        
        self.req_edit = QPlainTextEdit()
        self.req_edit.setFont(QFont("Consolas", 10))
        self.highlighter_req = HTTPHighlighter(self.req_edit.document(), is_request=True)
        req_layout.addWidget(self.req_edit)
        
        splitter.addWidget(req_group)
        
        # 响应显示区
        res_group = QGroupBox("响应")
        res_layout = QVBoxLayout(res_group)
        
        # 响应状态栏
        res_status_layout = QHBoxLayout()
        self.res_status_label = QLabel("")
        self.res_status_label.setStyleSheet(f"color: {COLORS['accent']}; font-weight: bold;")
        res_status_layout.addWidget(self.res_status_label)
        
        self.res_time_label = QLabel("")
        res_status_layout.addWidget(self.res_time_label)
        res_status_layout.addStretch()
        res_layout.addLayout(res_status_layout)
        
        self.res_display = QPlainTextEdit()
        self.res_display.setReadOnly(True)
        self.res_display.setFont(QFont("Consolas", 10))
        self.highlighter_res = HTTPHighlighter(self.res_display.document(), is_request=False)
        res_layout.addWidget(self.res_display)
        
        splitter.addWidget(res_group)
        
        splitter.setSizes([400, 400])
        
        layout.addWidget(splitter)
    
    def _go_prev(self):
        """上一个历史记录"""
        if self.history_index > 0:
            self.history_index -= 1
            self._load_history_item(self.history[self.history_index])
            self._update_nav_buttons()
    
    def _go_next(self):
        """下一个历史记录"""
        if self.history_index < len(self.history) - 1:
            self.history_index += 1
            self._load_history_item(self.history[self.history_index])
            self._update_nav_buttons()
    
    def _load_history_item(self, item: dict):
        """加载历史记录项"""
        self.url_input.setText(item.get('url', ''))
        self.method_combo.setCurrentText(item.get('method', 'POST'))
        self.req_edit.setPlainText(item.get('request', ''))
        self.res_display.setPlainText(item.get('response', ''))
        self._update_status_label(item.get('status_code', 0))
    
    def _update_nav_buttons(self):
        """更新导航按钮状态"""
        self.prev_btn.setEnabled(self.history_index > 0)
        self.next_btn.setEnabled(self.history_index < len(self.history) - 1)
    
    def _update_status_label(self, status_code: int):
        """更新状态标签"""
        status_text = f"状态码: {status_code}"
        if 200 <= status_code < 300:
            status_text += " OK"
            color = COLORS['success']
        elif 300 <= status_code < 400:
            status_text += " Redirect"
            color = COLORS['warning']
        elif 400 <= status_code < 500:
            status_text += " Client Error"
            color = COLORS['danger']
        else:
            status_text += " Server Error"
            color = "#ff6b6b"
        
        self.res_status_label.setText(status_text)
        self.res_status_label.setStyleSheet(f"color: {color}; font-weight: bold;")
    
    def load_request(self, request_data: dict):
        """加载请求"""
        method = request_data.get('method', 'GET')
        url = request_data.get('url', '')
        headers = request_data.get('request_headers', '')
        body = request_data.get('request_body', '')
        
        self.url_input.setText(url)
        self.method_combo.setCurrentText(method)
        
        # 构建请求文本
        req_text = f"{method} {url} HTTP/1.1\n"
        req_text += f"{headers}\n\n"
        req_text += body
        
        self.req_edit.setPlainText(req_text)
        self.res_display.clear()
        self.res_status_label.setText("")
    
    def _parse_request(self, req_text: str):
        """解析HTTP请求文本"""
        lines = req_text.strip().split('\n')
        if not lines:
            return None, None, None, None
        
        # 解析请求行
        first_line = lines[0].strip()
        parts = first_line.split(' ')
        if len(parts) < 2:
            return None, None, None, None
        
        method = parts[0]
        url = parts[1]
        
        # 解析请求头
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == '':
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        # 解析请求体
        body = '\n'.join(lines[body_start:]) if body_start > 0 else ''
        
        return method, url, headers, body
    
    def _send_request(self):
        """发送请求"""
        url = self.url_input.text().strip()
        method = self.method_combo.currentText()
        
        if not url:
            self.res_display.setPlainText("错误: 请输入目标URL")
            return
        
        # 解析请求文本
        req_text = self.req_edit.toPlainText()
        parsed_method, parsed_url, headers, body = self._parse_request(req_text)
        
        if parsed_url and parsed_url != '/':
            url = parsed_url
        if parsed_method:
            method = parsed_method
        
        # 禁用发送按钮
        self.send_btn.setEnabled(False)
        self.send_btn.setText("发送中...")
        
        # 创建工作线程
        request_data = {
            'url': url,
            'method': method,
            'headers': headers,
            'body': body
        }
        
        self.worker = RepeaterWorker(request_data)
        self.worker.finished.connect(self._on_request_finished)
        self.worker.error.connect(self._on_request_error)
        self.worker.start()
    
    def _on_request_finished(self, result: dict):
        """请求完成回调"""
        self.send_btn.setEnabled(True)
        self.send_btn.setText("发送")
        
        status_code = result['status_code']
        headers = result['headers']
        body = result['body']
        
        # 更新状态标签
        self._update_status_label(status_code)
        
        # 格式化响应
        res_text = f"HTTP/1.1 {status_code}\n"
        res_text += f"{headers}\n\n"
        res_text += body
        
        self.res_display.setPlainText(res_text)
        
        # 添加到历史记录
        history_item = {
            'url': self.url_input.text(),
            'method': self.method_combo.currentText(),
            'request': self.req_edit.toPlainText(),
            'response': res_text,
            'status_code': status_code
        }
        
        # 如果当前不在历史记录末尾，删除后面的记录
        if self.history_index < len(self.history) - 1:
            self.history = self.history[:self.history_index + 1]
        
        self.history.append(history_item)
        self.history_index = len(self.history) - 1
        self._update_nav_buttons()
        
        # 发送信号
        self.request_sent.emit(history_item, self.tab_name)
    
    def _on_request_error(self, error_msg: str):
        """请求错误回调"""
        self.send_btn.setEnabled(True)
        self.send_btn.setText("发送")
        self.res_display.setPlainText(f"请求错误: {error_msg}")
        self.res_status_label.setText("请求失败")
        self.res_status_label.setStyleSheet(f"color: {COLORS['danger']}; font-weight: bold;")


class RepeaterWidget(QWidget):
    """Repeater主界面 - 多标签支持"""
    
    def __init__(self):
        super().__init__()
        self.tab_counter = 1
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # 工具栏
        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(10, 10, 10, 5)
        
        new_tab_btn = QPushButton("+ 新建标签")
        new_tab_btn.clicked.connect(self._new_tab)
        toolbar.addWidget(new_tab_btn)
        
        close_tab_btn = QPushButton("关闭标签")
        close_tab_btn.clicked.connect(self._close_current_tab)
        toolbar.addWidget(close_tab_btn)
        
        toolbar.addStretch()
        
        layout.addLayout(toolbar)
        
        # 标签页
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.tabCloseRequested.connect(self._close_tab)
        self.tabs.tabBarDoubleClicked.connect(self._rename_tab)
        layout.addWidget(self.tabs)
        
        # 添加第一个标签
        self._new_tab()
    
    def _new_tab(self):
        """新建标签"""
        tab_name = f"Repeater {self.tab_counter}"
        tab = RepeaterTab(tab_name)
        index = self.tabs.addTab(tab, tab_name)
        self.tabs.setCurrentIndex(index)
        self.tab_counter += 1
    
    def _close_tab(self, index):
        """关闭指定标签"""
        if self.tabs.count() > 1:
            self.tabs.removeTab(index)
    
    def _close_current_tab(self):
        """关闭当前标签"""
        if self.tabs.count() > 1:
            self.tabs.removeTab(self.tabs.currentIndex())
    
    def _rename_tab(self, index):
        """重命名标签"""
        if index < 0:
            return
        old_name = self.tabs.tabText(index)
        new_name, ok = QInputDialog.getText(
            self,
            "重命名标签",
            "请输入新名称:",
            text=old_name
        )
        if ok and new_name.strip():
            self.tabs.setTabText(index, new_name.strip())
    
    def load_request(self, request_data: dict):
        """加载请求 - 新建标签页而不是覆盖"""
        # 先新建标签页
        self._new_tab()
        # 然后加载到新建的标签页
        current_tab = self.tabs.currentWidget()
        if current_tab and isinstance(current_tab, RepeaterTab):
            current_tab.load_request(request_data)
