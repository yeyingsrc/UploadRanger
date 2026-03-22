#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Repeater module with Payload Generation support.
"""

import asyncio
import re
import httpx
from PySide6.QtCore import Qt, Signal, QThread
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox,
    QPushButton, QSplitter, QGroupBox, QPlainTextEdit, QDialog, 
    QListWidget, QDialogButtonBox, QMessageBox, QCheckBox
)

from .themes.dark_theme import COLORS
from .syntax_highlighter import HTTPHighlighter
from .response_viewer import ResponseViewerWidget

# Import payload generators
try:
    from ..payloads.intruder_payloads import PayloadFactory, FuzzConfig, generate_intruder_payloads
    from ..payloads.bypass_payloads import BypassPayloadGenerator
    from ..core.response_analyzer import ResponseAnalyzer
except ImportError:
    from payloads.intruder_payloads import PayloadFactory, FuzzConfig, generate_intruder_payloads
    from payloads.bypass_payloads import BypassPayloadGenerator
    from core.response_analyzer import ResponseAnalyzer


class RepeaterWorker(QThread):
    finished = Signal(dict)
    error = Signal(str)

    def __init__(self, request_data: dict):
        super().__init__()
        self.request_data = request_data
        self._loop = None

    def run(self):
        try:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            result = self._loop.run_until_complete(self._send_request())
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))
        finally:
            if self._loop and not self._loop.is_closed():
                try:
                    self._loop.close()
                except Exception:
                    pass

    async def _send_request(self):
        url = self.request_data.get('url', '')
        method = self.request_data.get('method', 'GET')
        headers = self.request_data.get('headers', {})
        body = self.request_data.get('body', '')

        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        headers.pop('Content-Length', None)
        headers.pop('content-length', None)

        async with httpx.AsyncClient(verify=False, timeout=30, follow_redirects=True) as client:
            request_kwargs = {'headers': headers}
            if body:
                request_kwargs['content'] = body.encode('utf-8') if isinstance(body, str) else body

            if method == 'GET':
                response = await client.get(url, **request_kwargs)
            elif method == 'POST':
                response = await client.post(url, **request_kwargs)
            elif method == 'PUT':
                response = await client.put(url, **request_kwargs)
            elif method == 'DELETE':
                response = await client.delete(url, **request_kwargs)
            elif method == 'PATCH':
                response = await client.patch(url, **request_kwargs)
            else:
                response = await client.request(method, url, **request_kwargs)

            res_headers = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
            return {
                'status_code': response.status_code,
                'headers': res_headers,
                'body': response.text,
                'body_bytes': response.content,
                'url': str(response.url),
            }


class RepeaterTab(QWidget):
    request_sent = Signal(dict, str)

    def __init__(self, tab_name: str = "Repeater"):
        super().__init__()
        self.tab_name = tab_name
        self.worker = None
        
        # Initialize payload generators
        self.intruder_factory = PayloadFactory()
        self.bypass_generator = BypassPayloadGenerator()
        self.response_analyzer = ResponseAnalyzer()
        
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        control_layout = QHBoxLayout()
        control_layout.addWidget(QLabel("URL:"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("http://example.com")
        control_layout.addWidget(self.url_input)

        control_layout.addWidget(QLabel("Method:"))
        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
        control_layout.addWidget(self.method_combo)

        self.send_btn = QPushButton("Send")
        self.send_btn.setObjectName("success")
        self.send_btn.setFixedWidth(80)
        self.send_btn.clicked.connect(self._send_request)
        control_layout.addWidget(self.send_btn)

        # 新增: Payload生成按钮 - 【修复】增加宽度确保中文显示完整
        self.generate_payloads_btn = QPushButton("生成 Payloads")
        self.generate_payloads_btn.setFixedWidth(150)
        self.generate_payloads_btn.clicked.connect(self._on_generate_payloads)
        control_layout.addWidget(self.generate_payloads_btn)

        layout.addLayout(control_layout)

        splitter = QSplitter(Qt.Vertical)

        req_group = QGroupBox("Request")
        req_layout = QVBoxLayout(req_group)
        self.req_edit = QPlainTextEdit()
        self.req_edit.setFont(QFont("Consolas", 10))
        self.highlighter_req = HTTPHighlighter(self.req_edit.document(), is_request=True)
        # 【新增】启用自定义右键菜单
        self.req_edit.setContextMenuPolicy(Qt.CustomContextMenu)
        self.req_edit.customContextMenuRequested.connect(self._on_req_context_menu)
        req_layout.addWidget(self.req_edit)
        splitter.addWidget(req_group)

        res_group = QGroupBox("Response")
        res_layout = QVBoxLayout(res_group)
        self.res_status_label = QLabel("")
        self.res_status_label.setStyleSheet(f"color: {COLORS['accent']}; font-weight: bold;")
        res_layout.addWidget(self.res_status_label)
        self.res_display = ResponseViewerWidget()
        res_layout.addWidget(self.res_display)
        splitter.addWidget(res_group)

        splitter.setSizes([400, 400])
        layout.addWidget(splitter)

    def load_request(self, request_data: dict):
        method = request_data.get('method', 'GET')
        url = request_data.get('url', '')
        headers = request_data.get('request_headers', '')
        body = request_data.get('request_body', '')
        self.url_input.setText(url)
        self.method_combo.setCurrentText(method)
        req_text = f"{method} {url} HTTP/1.1\n{headers}\n\n{body}"
        self.req_edit.setPlainText(req_text)
        self.res_display.clear()
        self.res_status_label.setText("")

    def _parse_request(self, req_text: str):
        lines = req_text.strip().split('\n')
        if not lines:
            return None, None, None, None
        first_line = lines[0].strip().split(' ')
        if len(first_line) < 2:
            return None, None, None, None
        method = first_line[0]
        url = first_line[1]
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == '':
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        body = '\n'.join(lines[body_start:]) if body_start > 0 else ''
        return method, url, headers, body

    def _send_request(self):
        url = self.url_input.text().strip()
        if not url:
            self.res_display.raw_view.setPlainText("Error: URL required")
            return

        method = self.method_combo.currentText()
        req_text = self.req_edit.toPlainText()
        parsed_method, parsed_url, headers, body = self._parse_request(req_text)
        if parsed_url and parsed_url != '/':
            url = parsed_url
        if parsed_method:
            method = parsed_method

        self.send_btn.setEnabled(False)
        self.send_btn.setText("Sending...")

        self.worker = RepeaterWorker({
            'url': url,
            'method': method,
            'headers': headers,
            'body': body,
        })
        self.worker.finished.connect(self._on_request_finished)
        self.worker.error.connect(self._on_request_error)
        self.worker.start()

    def _on_request_finished(self, result: dict):
        self.send_btn.setEnabled(True)
        self.send_btn.setText("Send")

        status_code = result.get('status_code', 0)
        headers = result.get('headers', '')
        body = result.get('body', '')

        content_type = 'text/plain'
        for line in headers.split('\n'):
            if line.lower().startswith('content-type:'):
                content_type = line.split(':', 1)[1].strip()
                break

        self._update_status_label(status_code)
        
        # 使用ResponseAnalyzer分析响应，提取页面提示
        analysis = self._analyze_response(result)
        if analysis:
            # 将分析结果添加到响应中
            result['analysis'] = analysis
        
        self.res_display.set_response_from_dict(result)
    
    def _analyze_response(self, result: dict) -> dict:
        """分析响应内容，提取页面提示信息"""
        try:
            # 创建一个模拟的response对象
            class MockResponse:
                def __init__(self, result):
                    self.status_code = result.get('status_code', 0)
                    self.text = result.get('body', '')
                    self.content = result.get('body_bytes', b'')
                    self.headers = {}
                    self.url = result.get('url', '')
                    # 【修复】lambda需要接受self参数
                    self.elapsed = type('Elapsed', (), {'total_seconds': lambda self: 0})()
                    
                    # 解析headers
                    for line in result.get('headers', '').split('\n'):
                        if ':' in line:
                            k, v = line.split(':', 1)
                            self.headers[k.strip()] = v.strip()
            
            mock_resp = MockResponse(result)
            analysis = self.response_analyzer.analyze(mock_resp)
            
            # 简化返回结果
            return {
                'is_success': analysis.get('is_success', False),
                'is_failure': analysis.get('is_failure', False),
                'message': analysis.get('message', ''),
                'error_messages': analysis.get('error_messages', []),
                'warning_messages': analysis.get('warning_messages', []),
                'success_messages': analysis.get('success_messages', []),
                'hidden_indicators': analysis.get('hidden_indicators', []),
                'uploaded_path': analysis.get('uploaded_path', ''),
            }
        except Exception as e:
            return {'error': str(e)}

    def _on_request_error(self, error_msg: str):
        self.send_btn.setEnabled(True)
        self.send_btn.setText("Send")
        self.res_display.clear()
        self.res_display.raw_view.setPlainText(f"Request error: {error_msg}")
        self.res_status_label.setText("Request failed")
        self.res_status_label.setStyleSheet(f"color: {COLORS['danger']}; font-weight: bold;")

    def _update_status_label(self, status_code: int):
        status_text = f"Status: {status_code}"
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

    def _on_req_context_menu(self, pos):
        """【新增】请求编辑器的右键菜单"""
        # 获取标准右键菜单
        menu = self.req_edit.createStandardContextMenu()
        
        # 添加分隔符
        menu.addSeparator()
        
        # 添加"发送到Intruder"选项
        send_intruder_action = menu.addAction("发送到 Intruder")
        
        # 显示菜单并获取用户选择
        action = menu.exec(self.req_edit.mapToGlobal(pos))
        
        if action == send_intruder_action:
            self._send_to_intruder()
    
    def _send_to_intruder(self):
        """【新增】发送当前请求到Intruder"""
        req_text = self.req_edit.toPlainText()
        
        # 解析请求
        lines = req_text.strip().split('\n')
        if not lines:
            QMessageBox.warning(self, "警告", "请求内容为空")
            return
        
        first_line = lines[0].strip()
        parts = first_line.split(' ')
        if len(parts) < 2:
            QMessageBox.warning(self, "警告", "请求格式不正确")
            return
        
        method = parts[0]
        url = parts[1]
        
        # 解析headers
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == '':
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        body = '\n'.join(lines[body_start:]) if body_start > 0 else ''
        
        # 构建请求数据
        request_data = {
            'method': method,
            'url': url,
            'request_headers': '\n'.join([f"{k}: {v}" for k, v in headers.items()]),
            'request_body': body
        }
        
        # 发送信号到主窗口
        self.request_sent.emit(request_data, "intruder")

    def _on_generate_payloads(self):
        """生成文件上传绕过Payloads"""
        request_text = self.req_edit.toPlainText()
        
        # 检查是否包含文件上传相关内容
        if 'filename=' not in request_text and 'multipart' not in request_text.lower():
            QMessageBox.warning(
                self, 
                "提示", 
                "当前请求不包含文件上传表单 (multipart/form-data)\n"
                "请确保请求中包含 filename= 参数"
            )
            return
        
        # 显示Payload配置对话框
        dialog = PayloadConfigDialog(self)
        if dialog.exec() == QDialog.Accepted:
            config = dialog.get_config()
            
            # 生成Payloads
            try:
                payloads = self._generate_upload_payloads(request_text, config)
                
                # 显示Payload选择对话框
                select_dialog = PayloadSelectDialog(payloads, self)
                if select_dialog.exec() == QDialog.Accepted:
                    selected_payload = select_dialog.get_selected_payload()
                    if selected_payload:
                        # 将选中的payload填入请求编辑器
                        self.req_edit.setPlainText(selected_payload)
                        
            except Exception as e:
                QMessageBox.critical(self, "错误", f"生成Payload失败: {str(e)}")
    
    def _generate_upload_payloads(self, template: str, config: dict) -> list:
        """生成上传绕过Payloads
        
        Args:
            template: HTTP请求模板
            config: 配置字典
        
        Returns:
            List[str]: Payload列表
        """
        payloads = []
        
        # 使用Intruder Factory生成高级payloads
        languages = config.get('languages', ['php'])
        max_payloads = config.get('max_payloads', 100)
        
        intruder_payloads = generate_intruder_payloads(
            template, 
            languages=languages, 
            max_payloads=max_payloads
        )
        payloads.extend(intruder_payloads)
        
        # 使用Bypass Generator生成基础payloads
        if config.get('include_bypass', True):
            extensions = {
                'php': '.php',
                'asp': '.asp',
                'aspx': '.aspx',
                'jsp': '.jsp'
            }
            
            for lang in languages:
                if lang in extensions:
                    bypass_payloads = self.bypass_generator.generate_all_payloads(
                        "shell", extensions[lang]
                    )
                    for bp in bypass_payloads[:50]:  # 限制数量
                        # 替换模板中的filename
                        new_payload = re.sub(
                            r'filename="[^"]+"',
                            f'filename="{bp["filename"]}"',
                            template
                        )
                        payloads.append(new_payload)
        
        return payloads[:config.get('max_total', 200)]


class PayloadConfigDialog(QDialog):
    """Payload生成配置对话框"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Payload生成配置")
        self.setMinimumWidth(400)
        self._build_ui()
    
    def _build_ui(self):
        layout = QVBoxLayout(self)
        
        # 目标语言选择
        lang_group = QGroupBox("目标语言")
        lang_layout = QVBoxLayout(lang_group)
        
        self.php_cb = QCheckBox("PHP")
        self.php_cb.setChecked(True)
        self.asp_cb = QCheckBox("ASP")
        self.aspx_cb = QCheckBox("ASPX")
        self.jsp_cb = QCheckBox("JSP")
        
        lang_layout.addWidget(self.php_cb)
        lang_layout.addWidget(self.asp_cb)
        lang_layout.addWidget(self.aspx_cb)
        lang_layout.addWidget(self.jsp_cb)
        layout.addWidget(lang_group)
        
        # 选项
        options_group = QGroupBox("选项")
        options_layout = QVBoxLayout(options_group)
        
        self.bypass_cb = QCheckBox("包含基础绕过Payloads")
        self.bypass_cb.setChecked(True)
        self.bypass_cb.setToolTip("使用BypassPayloadGenerator生成基础绕过payloads")
        options_layout.addWidget(self.bypass_cb)
        
        layout.addWidget(options_group)
        
        # 按钮
        button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
    
    def get_config(self) -> dict:
        """获取配置"""
        languages = []
        if self.php_cb.isChecked():
            languages.append('php')
        if self.asp_cb.isChecked():
            languages.append('asp')
        if self.aspx_cb.isChecked():
            languages.append('aspx')
        if self.jsp_cb.isChecked():
            languages.append('jsp')
        
        return {
            'languages': languages if languages else ['php'],
            'include_bypass': self.bypass_cb.isChecked(),
            'max_payloads': 100,
            'max_total': 200
        }


class PayloadSelectDialog(QDialog):
    """Payload选择对话框"""
    
    def __init__(self, payloads: list, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"选择Payload ({len(payloads)}个可用)")
        self.setMinimumSize(800, 600)
        self.payloads = payloads
        self.selected_payload = None
        self._build_ui()
    
    def _build_ui(self):
        layout = QVBoxLayout(self)
        
        # Payload列表
        self.payload_list = QListWidget()
        self.payload_list.itemDoubleClicked.connect(self._on_item_double_clicked)
        
        # 添加payloads到列表 (显示filename)
        for i, payload in enumerate(self.payloads[:500]):  # 限制显示数量
            # 提取filename
            match = re.search(r'filename="([^"]+)"', payload)
            if match:
                filename = match.group(1)
                self.payload_list.addItem(f"[{i+1}] {filename}")
            else:
                self.payload_list.addItem(f"[{i+1}] Payload {i+1}")
        
        layout.addWidget(QLabel(f"共 {len(self.payloads)} 个Payloads (显示前500个)"))
        layout.addWidget(self.payload_list)
        
        # 预览区域
        preview_group = QGroupBox("预览")
        preview_layout = QVBoxLayout(preview_group)
        self.preview_edit = QPlainTextEdit()
        self.preview_edit.setReadOnly(True)
        self.preview_edit.setFont(QFont("Consolas", 9))
        preview_layout.addWidget(self.preview_edit)
        layout.addWidget(preview_group)
        
        # 连接选择信号
        self.payload_list.currentRowChanged.connect(self._on_selection_changed)
        
        # 按钮
        button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
    
    def _on_selection_changed(self, row: int):
        """选择改变时更新预览"""
        if 0 <= row < len(self.payloads):
            payload = self.payloads[row]
            # 显示payload的前1000个字符
            preview = payload[:1000] + "..." if len(payload) > 1000 else payload
            self.preview_edit.setPlainText(preview)
    
    def _on_item_double_clicked(self, item):
        """双击选择"""
        self.accept()
    
    def get_selected_payload(self) -> str:
        """获取选中的payload"""
        row = self.payload_list.currentRow()
        if 0 <= row < len(self.payloads):
            return self.payloads[row]
        return None
    
    def accept(self):
        """确认选择"""
        row = self.payload_list.currentRow()
        if row < 0:
            QMessageBox.warning(self, "提示", "请先选择一个Payload")
            return
        self.selected_payload = self.payloads[row] if row < len(self.payloads) else None
        super().accept()


class RepeaterWidget(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        self.tab = RepeaterTab("Repeater")
        layout.addWidget(self.tab)

    def load_request(self, request_data: dict):
        self.tab.load_request(request_data)
