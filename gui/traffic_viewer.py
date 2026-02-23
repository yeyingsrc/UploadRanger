#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
流量查看器 - 类似Burp的请求/响应查看
支持分割器调整大小，完整内容显示，语法高亮
"""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, 
    QTableWidgetItem, QSplitter, QLabel, 
    QHeaderView, QPushButton, QMenu, QPlainTextEdit, QApplication
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont, QAction, QTextCursor

from .themes.dark_theme import COLORS
from .syntax_highlighter import HTTPHighlighter


class CodeEditor(QPlainTextEdit):
    """带语法高亮的代码编辑器"""
    
    def __init__(self, parent=None, is_request=True):
        super().__init__(parent)
        self.is_request = is_request
        
        # 设置字体
        self.setFont(QFont("Consolas", 10))
        
        # 设置样式
        self.setStyleSheet(f"""
            QPlainTextEdit {{
                background-color: {COLORS['bg_secondary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                padding: 8px;
            }}
        """)
        
        # 添加语法高亮
        self.highlighter = HTTPHighlighter(self.document(), is_request)
    
    def setPlainText(self, text):
        """设置文本并滚动到顶部"""
        super().setPlainText(text)
        self.moveCursor(QTextCursor.Start)


class TrafficViewer(QWidget):
    """流量查看器 - 显示请求/响应历史，支持发送到Repeater和Intruder"""
    
    # 信号
    send_to_repeater = Signal(dict)  # 发送到Repeater
    send_to_intruder = Signal(dict)  # 发送到Intruder
    
    def __init__(self):
        super().__init__()
        self.logs = []
        self.current_log = None
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        # 使用水平分割器 - 左侧请求列表，右侧详情
        main_splitter = QSplitter(Qt.Horizontal)
        
        # 左侧: 请求列表
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(5)
        
        # 标题和清除按钮
        header_layout = QHBoxLayout()
        header_label = QLabel("请求历史")
        header_label.setStyleSheet(f"font-weight: bold; color: {COLORS['accent']};")
        header_layout.addWidget(header_label)
        
        clear_btn = QPushButton("清除")
        clear_btn.setFixedWidth(60)
        clear_btn.clicked.connect(self.clear_logs)
        header_layout.addWidget(clear_btn)
        
        left_layout.addLayout(header_layout)
        
        # 请求列表表格
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["ID", "时间", "方法", "URL", "状态码"])
        self.table.setColumnWidth(0, 50)
        self.table.setColumnWidth(1, 70)
        self.table.setColumnWidth(2, 60)
        self.table.setColumnWidth(4, 70)
        
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.Fixed)
        
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.itemClicked.connect(self.display_details)
        self.table.setAlternatingRowColors(True)
        
        # 右键菜单
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        
        left_layout.addWidget(self.table)
        
        # 右侧: 请求/响应详情 - 使用垂直分割器
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(5)
        
        # 垂直分割器 - 上半部分请求，下半部分响应
        vertical_splitter = QSplitter(Qt.Vertical)
        
        # 请求详情
        req_widget = QWidget()
        req_layout = QVBoxLayout(req_widget)
        req_layout.setContentsMargins(0, 0, 0, 0)
        req_layout.setSpacing(5)
        
        req_header = QHBoxLayout()
        req_label = QLabel("请求")
        req_label.setStyleSheet(f"font-weight: bold; color: {COLORS['accent']};")
        req_header.addWidget(req_label)
        
        # 发送到Repeater按钮
        self.repeater_btn = QPushButton("发送到 Repeater")
        self.repeater_btn.setFixedWidth(130)
        self.repeater_btn.clicked.connect(self._send_to_repeater)
        self.repeater_btn.setEnabled(False)
        self.repeater_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['accent']};
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent_hover']};
            }}
        """)
        req_header.addWidget(self.repeater_btn)
        
        # 发送到Intruder按钮
        self.intruder_btn = QPushButton("发送到 Intruder")
        self.intruder_btn.setFixedWidth(130)
        self.intruder_btn.clicked.connect(self._send_to_intruder)
        self.intruder_btn.setEnabled(False)
        self.intruder_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['warning']};
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #d4a017;
            }}
        """)
        req_header.addWidget(self.intruder_btn)
        
        req_layout.addLayout(req_header)
        
        # 使用带语法高亮的编辑器
        self.req_text = CodeEditor(is_request=True)
        self.req_text.setReadOnly(True)
        req_layout.addWidget(self.req_text)
        
        vertical_splitter.addWidget(req_widget)
        
        # 响应详情
        res_widget = QWidget()
        res_layout = QVBoxLayout(res_widget)
        res_layout.setContentsMargins(0, 0, 0, 0)
        res_layout.setSpacing(5)
        
        res_header = QHBoxLayout()
        res_label = QLabel("响应")
        res_label.setStyleSheet(f"font-weight: bold; color: {COLORS['accent']};")
        res_header.addWidget(res_label)
        
        # 状态码显示
        self.status_label = QLabel("")
        self.status_label.setStyleSheet(f"color: {COLORS['accent']}; font-weight: bold;")
        res_header.addWidget(self.status_label)
        res_header.addStretch()
        
        res_layout.addLayout(res_header)
        
        # 使用带语法高亮的编辑器
        self.res_text = CodeEditor(is_request=False)
        self.res_text.setReadOnly(True)
        res_layout.addWidget(self.res_text)
        
        vertical_splitter.addWidget(res_widget)
        
        # 设置垂直分割器比例
        vertical_splitter.setSizes([400, 400])
        
        right_layout.addWidget(vertical_splitter)
        
        # 添加到水平分割器
        main_splitter.addWidget(left_widget)
        main_splitter.addWidget(right_widget)
        main_splitter.setSizes([500, 900])
        main_splitter.setStretchFactor(0, 1)
        main_splitter.setStretchFactor(1, 2)
        
        layout.addWidget(main_splitter)
    
    def show_context_menu(self, position):
        """显示右键菜单"""
        menu = QMenu(self)
        
        send_repeater_action = QAction("发送到 Repeater", self)
        send_repeater_action.triggered.connect(self._send_to_repeater)
        menu.addAction(send_repeater_action)
        
        send_intruder_action = QAction("发送到 Intruder", self)
        send_intruder_action.triggered.connect(self._send_to_intruder)
        menu.addAction(send_intruder_action)
        
        menu.addSeparator()
        
        copy_url_action = QAction("复制 URL", self)
        copy_url_action.triggered.connect(self._copy_url)
        menu.addAction(copy_url_action)
        
        menu.exec(self.table.viewport().mapToGlobal(position))
    
    def _send_to_repeater(self):
        """发送到Repeater"""
        if self.current_log:
            self.send_to_repeater.emit(self.current_log.to_dict())
    
    def _send_to_intruder(self):
        """发送到Intruder"""
        if self.current_log:
            self.send_to_intruder.emit(self.current_log.to_dict())
    
    def _copy_url(self):
        """复制URL"""
        if self.current_log:
            clipboard = QApplication.clipboard()
            clipboard.setText(self.current_log.url)
    
    def clear_logs(self):
        """清除所有日志"""
        self.logs = []
        self.table.setRowCount(0)
        self.req_text.clear()
        self.res_text.clear()
        self.current_log = None
        self.repeater_btn.setEnabled(False)
        self.intruder_btn.setEnabled(False)
        self.status_label.setText("")
    
    def add_log(self, log):
        """添加流量日志"""
        self.logs.append(log)
        row = self.table.rowCount()
        self.table.insertRow(row)
        
        # ID
        self.table.setItem(row, 0, QTableWidgetItem(str(log.id)))
        # 时间
        self.table.setItem(row, 1, QTableWidgetItem(log.timestamp))
        # 方法
        method_item = QTableWidgetItem(log.method)
        self.table.setItem(row, 2, method_item)
        # URL
        url_item = QTableWidgetItem(log.url)
        url_item.setToolTip(log.url)
        self.table.setItem(row, 3, url_item)
        # 状态码
        status_item = QTableWidgetItem(str(log.status_code))
        
        # 根据状态码设置颜色
        if 200 <= log.status_code < 300:
            status_item.setForeground(QColor(COLORS['success']))
        elif 300 <= log.status_code < 400:
            status_item.setForeground(QColor(COLORS['warning']))
        elif 400 <= log.status_code < 500:
            status_item.setForeground(QColor(COLORS['danger']))
        elif 500 <= log.status_code:
            status_item.setForeground(QColor("#ff6b6b"))
        
        self.table.setItem(row, 4, status_item)
        
        # 滚动到最新行
        self.table.scrollToBottom()
    
    def display_details(self, item):
        """显示选中请求的详情"""
        row = item.row()
        if row < len(self.logs):
            log = self.logs[row]
            self.current_log = log
            self.repeater_btn.setEnabled(True)
            self.intruder_btn.setEnabled(True)
            
            # 格式化请求 - 显示完整内容
            req_str = f"{log.method} {log.url} HTTP/1.1\n"
            req_str += f"{log.request_headers}\n\n"
            req_str += f"{log.request_body}"
            self.req_text.setPlainText(req_str)
            
            # 格式化响应 - 显示完整内容
            res_str = f"HTTP/1.1 {log.status_code}\n"
            res_str += f"{log.response_headers}\n\n"
            res_str += f"{log.response_body}"
            self.res_text.setPlainText(res_str)
            
            # 更新状态码显示
            status_text = f"状态码: {log.status_code}"
            if 200 <= log.status_code < 300:
                status_text += " OK"
                color = COLORS['success']
            elif 300 <= log.status_code < 400:
                status_text += " Redirect"
                color = COLORS['warning']
            elif 400 <= log.status_code < 500:
                status_text += " Client Error"
                color = COLORS['danger']
            elif 500 <= log.status_code:
                status_text += " Server Error"
                color = "#ff6b6b"
            else:
                color = COLORS['text_secondary']
            
            self.status_label.setText(status_text)
            self.status_label.setStyleSheet(f"color: {color}; font-weight: bold;")
