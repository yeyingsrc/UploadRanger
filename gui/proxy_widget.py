#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
代理模块 - 基于 mitmproxy 的 HTTP/HTTPS 代理
支持拦截、放包、丢弃、修改后放行、发送到Repeater/Intruder
"""

import asyncio
import threading
import time
import os
from typing import Dict, Optional
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit,
    QPushButton, QComboBox, QLabel, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter, QGroupBox, QCheckBox, QPlainTextEdit,
    QApplication, QTabWidget, QFrame, QMessageBox, QMenu, QDialog,
    QDialogButtonBox, QTextEdit as QDialogTextEdit
)
from PySide6.QtCore import Qt, Signal, QThread, QObject
from PySide6.QtGui import QColor, QFont

from .themes.dark_theme import COLORS
from .syntax_highlighter import HTTPHighlighter
from core.config_manager import ConfigManager

# 尝试导入 mitmproxy
try:
    from mitmproxy import http
    from mitmproxy.tools.dump import DumpMaster
    from mitmproxy import options
    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False
    print("警告: mitmproxy 未安装，代理功能将不可用")


class ProxySignals(QObject):
    """代理信号类 - 用于跨线程通信"""
    request_intercepted = Signal(object)  # 请求被拦截
    response_received = Signal(object, object)  # 收到响应
    request_logged = Signal(object)  # 请求被记录
    status_changed = Signal(str)  # 状态改变


class InterceptedFlow:
    """被拦截的流量对象"""
    def __init__(self, flow_id, method, url, headers, content, is_https=False):
        self.id = flow_id
        self.method = method
        self.url = url
        self.host = headers.get('Host', '')
        self.headers = headers
        self.content = content
        self.is_https = is_https
        self.timestamp = time.strftime("%H:%M:%S")
        self.status_code = '-'
        self.response_headers = {}
        self.response_content = b''
        self.intercepted = True
        self.released = False
        self.dropped = False
        self.modified = False
        self._event = None  # asyncio.Event
        self._flow = None  # mitmproxy flow
    
    def set_event(self, event):
        """设置异步事件"""
        self._event = event
    
    def set_flow(self, flow):
        """设置 mitmproxy flow"""
        self._flow = flow
    
    def to_dict(self):
        """转换为字典格式"""
        return {
            'method': self.method,
            'url': self.url,
            'host': self.host,
            'request_headers': '\n'.join([f"{k}: {v}" for k, v in self.headers.items()]),
            'request_body': self.content.decode('utf-8', errors='ignore') if self.content else ''
        }


class UploadRangerAddon:
    """mitmproxy 插件 - 处理流量拦截"""
    
    def __init__(self, signals: ProxySignals, intercept_enabled: bool = True):
        self.signals = signals
        self.intercept_enabled = intercept_enabled
        self.waiting_flows: Dict[str, tuple] = {}  # {flow_id: (flow, event, intercepted_flow)}
        self.flow_counter = 0
        self._pending_tasks: list = []  # 【新增】跟踪所有待处理任务
    
    def set_intercept(self, enabled: bool):
        """设置是否拦截"""
        self.intercept_enabled = enabled
    
    def request(self, flow):
        """处理请求 - 修复：使用flow.intercept()非阻塞拦截，优化本地请求处理"""
        self.flow_counter += 1
        flow_id = str(self.flow_counter)
        
        # 【优化】确保URL正确，处理本地请求
        url = flow.request.url
        # 如果是本地请求，确保URL格式正确
        if flow.request.host in ['127.0.0.1', 'localhost', '::1']:
            # 本地请求正常处理
            pass
        
        # 创建拦截对象
        intercepted = InterceptedFlow(
            flow_id=flow_id,
            method=flow.request.method,
            url=url,
            headers=dict(flow.request.headers),
            content=flow.request.content if flow.request.content else b''
        )
        intercepted.set_flow(flow)
        
        # 如果需要拦截
        if self.intercept_enabled:
            # 【关键修复】使用 mitmproxy 的 flow.intercept() 非阻塞拦截
            flow.intercept()
            
            # 创建异步事件用于等待用户操作
            event = asyncio.Event()
            intercepted.set_event(event)
            
            # 存储等待中的 flow
            self.waiting_flows[flow_id] = (flow, event, intercepted)
            
            # 通知 GUI（使用信号，非阻塞）
            self.signals.request_intercepted.emit(intercepted)
            
            # 创建等待任务（异步，不阻塞事件循环）
            asyncio.create_task(self._wait_for_action(flow_id, event))
        else:
            # 不拦截，直接记录
            intercepted.intercepted = False
            self.signals.request_logged.emit(intercepted)
            # 存储以便后续关联响应
            self.waiting_flows[flow_id] = (flow, None, intercepted)
    
    async def _wait_for_action(self, flow_id: str, event: asyncio.Event):
        """等待用户操作 - 异步等待，不阻塞事件循环"""
        try:
            # 【优化】减少超时时间到60秒，提高响应速度
            await asyncio.wait_for(event.wait(), timeout=60)
        except asyncio.TimeoutError:
            # 超时后自动放行
            if flow_id in self.waiting_flows:
                flow, _, intercepted = self.waiting_flows[flow_id]
                try:
                    flow.resume()
                except Exception:
                    pass
                intercepted.released = True
                if flow_id in self.waiting_flows:
                    del self.waiting_flows[flow_id]
        except asyncio.CancelledError:
            # 任务被取消，清理
            if flow_id in self.waiting_flows:
                flow, event, intercepted = self.waiting_flows[flow_id]
                try:
                    flow.kill()  # 取消时丢弃请求
                except Exception:
                    pass
                intercepted.released = True
                del self.waiting_flows[flow_id]
        except Exception:
            pass
        finally:
            # 清理
            if flow_id in self.waiting_flows:
                del self.waiting_flows[flow_id]
    
    def cancel_all_tasks(self):
        """取消所有待处理任务"""
        # 直接清空等待列表，mitmproxy 会自动处理
        self.waiting_flows.clear()
    
    def handle_action(self, flow_id: str, action: str, modified_content: bytes = None):
        """处理用户操作 - 由 GUI 线程调用"""
        if flow_id not in self.waiting_flows:
            return
        
        flow, event, intercepted = self.waiting_flows[flow_id]
        
        if action == "forward":
            # 如果提供了修改后的内容
            if modified_content is not None:
                flow.request.content = modified_content
                flow.request.headers["Content-Length"] = str(len(modified_content))
                intercepted.modified = True
            # 【关键】调用 resume() 放行，而不是 kill()
            flow.resume()
            intercepted.released = True
        elif action == "drop":
            flow.kill()
            intercepted.dropped = True
            intercepted.released = True
        
        # 唤醒等待的协程
        if event:
            event.set()
    
    def response(self, flow):
        """处理响应 - 优化响应处理速度"""
        # 查找对应的请求 - 优化查找逻辑
        found = False
        for flow_id, (f, event, intercepted) in list(self.waiting_flows.items()):
            if f.id == flow.id:
                # 更新响应信息
                intercepted.status_code = flow.response.status_code
                intercepted.response_headers = dict(flow.response.headers)
                intercepted.response_content = flow.response.content if flow.response.content else b''
                
                # 通知 GUI
                self.signals.response_received.emit(intercepted, flow)
                found = True
                break
        
        # 如果没有找到对应的请求（可能是不拦截模式），创建新的记录
        if not found:
            self.flow_counter += 1
            flow_id = str(self.flow_counter)
            intercepted = InterceptedFlow(
                flow_id=flow_id,
                method=flow.request.method,
                url=flow.request.url,
                headers=dict(flow.request.headers),
                content=flow.request.content if flow.request.content else b''
            )
            intercepted.status_code = flow.response.status_code
            intercepted.response_headers = dict(flow.response.headers)
            intercepted.response_content = flow.response.content if flow.response.content else b''
            intercepted.intercepted = False
            self.signals.request_logged.emit(intercepted)
            self.signals.response_received.emit(intercepted, flow)


class ProxyThread(QThread):
    """代理线程 - 在独立线程中运行 mitmproxy"""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        super().__init__()
        self.host = host
        self.port = port
        self.signals = ProxySignals()
        self.addon = None
        self.master = None
        self.loop = None
        self._running = False
        # 【修复】使用实例变量以便 stop() 方法可以访问
        self._stop_event = None
    
    def set_intercept(self, enabled: bool):
        """设置是否拦截"""
        if self.addon:
            self.addon.set_intercept(enabled)
    
    def forward_request(self, flow_id: str, modified_content: bytes = None):
        """放行请求"""
        if self.addon and self.loop:
            self.loop.call_soon_threadsafe(
                self.addon.handle_action, flow_id, "forward", modified_content
            )
    
    def drop_request(self, flow_id: str):
        """丢弃请求"""
        if self.addon and self.loop:
            self.loop.call_soon_threadsafe(
                self.addon.handle_action, flow_id, "drop"
            )
    
    def run(self):
        """线程的主入口"""
        import sys
        
        if not MITMPROXY_AVAILABLE:
            self.signals.status_changed.emit("错误: mitmproxy 未安装")
            return

        # 【修复】禁用 mitmproxy 的日志处理器，避免程序退出时事件循环关闭后报错
        import logging
        # 保存原始日志级别
        self._original_loglevel = logging.root.level
        # 设置更高的日志级别，过滤掉 mitmproxy 的日志
        logging.root.setLevel(logging.CRITICAL)

        # 【修复】为子线程创建独立的事件循环
        self.loop = asyncio.new_event_loop()
        
        # Linux 环境下使用 DefaultSelector
        if sys.platform.startswith('linux'):
            self.loop = asyncio.SelectorEventLoop()
        
        # 设置事件循环
        asyncio.set_event_loop(self.loop)

        # 【修复】使用更可靠的方式运行异步代码
        async def run_proxy():
            """运行代理，并在停止时正确等待"""
            # 创建 mitmproxy master（必须在事件循环内创建）
            opts = options.Options(
                listen_host=self.host,
                listen_port=self.port,
                ssl_insecure=True
            )
            self.master = DumpMaster(opts, with_termlog=False, with_dumper=False)

            # 创建插件
            self.addon = UploadRangerAddon(self.signals)
            self.master.addons.add(self.addon)

            self._running = True
            self.signals.status_changed.emit(f"代理运行中: {self.host}:{self.port}")

            # 创建停止事件
            self._stop_event = asyncio.Event()

            async def wait_for_stop():
                """等待停止信号"""
                while not self._stop_event.is_set():
                    await asyncio.sleep(0.1)
                self._running = False

            # 同时运行 master 和等待停止
            master_task = asyncio.create_task(self.master.run())
            stop_task = asyncio.create_task(wait_for_stop())

            try:
                # 等待任一任务完成
                done, pending = await asyncio.wait(
                    [master_task, stop_task],
                    return_when=asyncio.FIRST_COMPLETED
                )

                # 先关闭 master
                try:
                    self.master.shutdown()
                except Exception:
                    pass

                # 取消 pending 任务
                for task in pending:
                    task.cancel()
                    try:
                        await asyncio.wait_for(task, timeout=2.0)
                    except (asyncio.CancelledError, asyncio.TimeoutError, asyncio.InvalidStateError):
                        pass

            except asyncio.CancelledError:
                try:
                    self.master.shutdown()
                except Exception:
                    pass
            except Exception as e:
                self.signals.status_changed.emit(f"代理异常: {str(e)}")

        # 使用 run_until_complete 运行协程
        try:
            self.loop.run_until_complete(run_proxy())
        except (asyncio.CancelledError, RuntimeError) as e:
            # 用户主动停止或事件循环已关闭 - 这是正常现象，不显示错误
            if "Event loop stopped" in str(e):
                self.signals.status_changed.emit("代理已停止")
            else:
                self.signals.status_changed.emit(f"代理线程退出: {str(e)}")
        except Exception as e:
            self.signals.status_changed.emit(f"代理异常: {str(e)}")
        finally:
            self._running = False

            # 【方案A修复】在 finally 块中也进行彻底清理
            import time
            
            # 1. 首先尝试取消所有 asyncio 任务
            if self.loop and not self.loop.is_closed():
                try:
                    async def cleanup_tasks():
                        """清理所有待处理任务"""
                        try:
                            all_tasks = asyncio.all_tasks(self.loop)
                            pending = [t for t in all_tasks if not t.done()]
                            if pending:
                                for t in pending:
                                    t.cancel()
                                await asyncio.wait(pending, timeout=1.0)
                        except Exception:
                            pass
                    
                    if self.loop.is_running():
                        self.loop.run_until_complete(cleanup_tasks())
                except Exception:
                    pass
            
            time.sleep(0.1)

            # 2. 先移除 mitmproxy 的日志处理器，避免事件循环关闭后报错
            if hasattr(self, 'master') and self.master:
                try:
                    # 移除所有日志处理器
                    import logging
                    for handler in logging.root.handlers[:]:
                        if hasattr(handler, 'master'):
                            logging.root.removeHandler(handler)
                except Exception:
                    pass

                # 再关闭 master
                try:
                    self.master.shutdown()
                except Exception:
                    pass

            time.sleep(0.1)

            # 3. 清空等待列表
            if self.addon:
                self.addon.cancel_all_tasks()

            # 4. 关闭事件循环
            if self.loop and not self.loop.is_closed():
                try:
                    # 停止事件循环，这会取消所有正在等待的任务
                    self.loop.stop()
                except Exception:
                    pass

                time.sleep(0.1)
                
                # 关闭循环
                try:
                    self.loop.close()
                except Exception:
                    pass

            # 5. 清理引用
            self.loop = None
            self.master = None
            self.addon = None
            
            # 【修复】恢复日志级别
            if hasattr(self, '_original_loglevel'):
                import logging
                logging.root.setLevel(self._original_loglevel)

    def stop(self):
        """停止代理 - 彻底清理所有资源"""
        self._running = False
        import time

        # 【修复】使用 run_coroutine_threadsafe 在运行中的事件循环中调度取消任务
        if self.loop and not self.loop.is_closed() and self.loop.is_running():
            try:
                async def cancel_all_tasks():
                    """取消事件循环中的所有待处理任务"""
                    try:
                        all_tasks = asyncio.all_tasks(self.loop)
                        pending_tasks = [t for t in all_tasks if not t.done() and t != asyncio.current_task()]
                        
                        if pending_tasks:
                            for task in pending_tasks:
                                task.cancel()
                            # 等待所有任务完成取消（设置较短的超时）
                            await asyncio.wait_for(
                                asyncio.gather(*pending_tasks, return_exceptions=True),
                                timeout=1.0
                            )
                    except Exception:
                        pass

                # 使用 run_coroutine_threadsafe 在运行中的事件循环中调度任务
                future = asyncio.run_coroutine_threadsafe(cancel_all_tasks(), self.loop)
                # 等待取消操作完成，最多等待1.5秒
                try:
                    future.result(timeout=1.5)
                except Exception:
                    pass  # 忽略超时或取消异常
            except Exception:
                pass

        # 等待任务取消完成
        time.sleep(0.2)

        # 设置停止事件
        if self._stop_event:
            try:
                self._stop_event.set()
            except Exception:
                pass

        # 等待一小段时间
        time.sleep(0.2)

        # 确保 master 已关闭
        if hasattr(self, 'master') and self.master:
            try:
                self.master.shutdown()
            except Exception:
                pass

        # 等待 master 关闭
        time.sleep(0.3)

        # 强制停止事件循环（作为最后手段）
        if self.loop:
            try:
                if self.loop.is_running():
                    self.loop.call_soon_threadsafe(self.loop.stop)
                time.sleep(0.2)
                if not self.loop.is_closed():
                    self.loop.close()
            except Exception as e:
                print(f"停止事件循环时出错: {e}")

        # 清理引用，帮助 GC
        self._stop_event = None
        self.master = None
        self.addon = None
        self.loop = None  # 彻底清理，不复用


class ProxyHistoryTab(QWidget):
    """代理历史标签页"""
    
    send_to_repeater = Signal(object)
    send_to_intruder = Signal(object)
    
    def __init__(self, proxy_thread: 'ProxyThread' = None, config_manager: ConfigManager = None):
        super().__init__()
        self.proxy_thread = proxy_thread
        self.config_manager = config_manager
        self.history = []
        
        # 【修复】初始化过滤规则
        self.filter_rules = ""
        
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        # 工具栏
        toolbar = QHBoxLayout()
        
        clear_btn = QPushButton("清空历史")
        clear_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                padding: 5px 15px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['border']};
            }}
        """)
        clear_btn.clicked.connect(self.clear_history)
        toolbar.addWidget(clear_btn)
        
        # 【修复】简化的过滤控制区域 - 删除复选框，只保留按钮和统计
        filter_control_layout = QHBoxLayout()
        filter_control_layout.setSpacing(10)
        
        # 【修复】配置过滤按钮 - 点击弹出对话框
        self.filter_config_btn = QPushButton("配置过滤规则...")
        self.filter_config_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                padding: 5px 15px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['border']};
            }}
        """)
        self.filter_config_btn.clicked.connect(self._open_filter_dialog)
        filter_control_layout.addWidget(self.filter_config_btn)
        
        # 过滤统计标签
        self.filter_stats_label = QLabel("已显示 0 / 总计 0 条")
        self.filter_stats_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px;")
        filter_control_layout.addWidget(self.filter_stats_label)
        
        filter_control_layout.addStretch()
        
        toolbar.addLayout(filter_control_layout)
        
        toolbar.addStretch()
        
        to_repeater_btn = QPushButton("发送到 Repeater")
        to_repeater_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['accent']};
                color: white;
                border: none;
                padding: 5px 15px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent_hover']};
            }}
        """)
        to_repeater_btn.clicked.connect(self._send_to_repeater)
        toolbar.addWidget(to_repeater_btn)
        
        to_intruder_btn = QPushButton("发送到 Intruder")
        to_intruder_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['warning']};
                color: white;
                border: none;
                padding: 5px 15px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #d97706;
            }}
        """)
        to_intruder_btn.clicked.connect(self._send_to_intruder)
        toolbar.addWidget(to_intruder_btn)
        
        layout.addLayout(toolbar)
        
        # 历史列表
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(6)
        self.history_table.setHorizontalHeaderLabels(["ID", "时间", "方法", "URL", "状态码", "拦截"])
        self.history_table.setColumnWidth(0, 50)
        self.history_table.setColumnWidth(1, 70)
        self.history_table.setColumnWidth(2, 60)
        self.history_table.setColumnWidth(4, 70)
        self.history_table.setColumnWidth(5, 50)
        
        header = self.history_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.Fixed)
        header.setSectionResizeMode(5, QHeaderView.Fixed)
        
        self.history_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.history_table.setAlternatingRowColors(True)
        self.history_table.setEditTriggers(QTableWidget.NoEditTriggers) 
        self.history_table.itemClicked.connect(self._on_item_selected)
        # 启用右键菜单
        self.history_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.history_table.customContextMenuRequested.connect(self._on_context_menu)
        
        # 【修复】添加行高和选中样式优化 - 移除选中边框避免覆盖URL
        self.history_table.verticalHeader().setDefaultSectionSize(28)
        self.history_table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLORS['bg_secondary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                gridline-color: {COLORS['border']};
            }}
            QTableWidget::item {{
                padding: 4px 8px;
                border: none;
            }}
            QTableWidget::item:selected {{
                background-color: {COLORS['accent']};
                color: white;
                border: none;
                outline: none;
            }}
            QTableWidget::item:focus {{
                border: none;
                outline: none;
            }}
            QTableWidget:focus {{
                border: 1px solid {COLORS['accent']};
                outline: none;
            }}
            QHeaderView::section {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_primary']};
                padding: 8px;
                border: none;
                border-right: 1px solid {COLORS['border']};
                border-bottom: 1px solid {COLORS['border']};
                font-weight: bold;
            }}
        """)
        
        layout.addWidget(self.history_table)
        
        # 详情区域
        splitter = QSplitter(Qt.Vertical)
        splitter.setHandleWidth(6)
        splitter.setStyleSheet(f"""
            QSplitter::handle {{
                background-color: {COLORS['border']};
            }}
            QSplitter::handle:hover {{
                background-color: {COLORS['accent']};
            }}
        """)
        
        # 请求详情
        req_group = QGroupBox("请求")
        req_group.setStyleSheet(f"""
            QGroupBox {{
                font-weight: bold;
                color: {COLORS['accent']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                margin-top: 12px;
                padding-top: 10px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
            }}
        """)
        req_layout = QVBoxLayout(req_group)
        req_layout.setContentsMargins(5, 5, 5, 5)
        
        self.req_detail = QPlainTextEdit()
        self.req_detail.setReadOnly(True)
        self.req_detail.setFont(QFont("Consolas", 9))
        self.highlighter_req = HTTPHighlighter(self.req_detail.document(), is_request=True)
        req_layout.addWidget(self.req_detail)
        
        splitter.addWidget(req_group)
        
        # 响应详情
        res_group = QGroupBox("响应")
        res_group.setStyleSheet(f"""
            QGroupBox {{
                font-weight: bold;
                color: {COLORS['accent']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                margin-top: 12px;
                padding-top: 10px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
            }}
        """)
        res_layout = QVBoxLayout(res_group)
        res_layout.setContentsMargins(5, 5, 5, 5)
        
        self.res_detail = QPlainTextEdit()
        self.res_detail.setReadOnly(True)
        self.res_detail.setFont(QFont("Consolas", 9))
        self.highlighter_res = HTTPHighlighter(self.res_detail.document(), is_request=False)
        res_layout.addWidget(self.res_detail)
        
        splitter.addWidget(res_group)
        
        splitter.setSizes([300, 300])
        
        layout.addWidget(splitter)
    
    def add_request(self, intercepted: InterceptedFlow):
        """【修复】添加请求到历史 - 自动应用过滤规则"""
        self.history.append(intercepted)
        
        row = self.history_table.rowCount()
        self.history_table.insertRow(row)
        
        id_item = QTableWidgetItem(str(intercepted.id))
        id_item.setData(Qt.UserRole, intercepted)
        self.history_table.setItem(row, 0, id_item)
        
        self.history_table.setItem(row, 1, QTableWidgetItem(intercepted.timestamp))
        self.history_table.setItem(row, 2, QTableWidgetItem(intercepted.method))
        
        url_item = QTableWidgetItem(intercepted.url[:80])
        url_item.setToolTip(intercepted.url)
        self.history_table.setItem(row, 3, url_item)
        
        status_item = QTableWidgetItem(str(intercepted.status_code))
        if intercepted.status_code != '-':
            try:
                code = int(intercepted.status_code)
                if 200 <= code < 300:
                    status_item.setForeground(QColor(COLORS['success']))
                elif 300 <= code < 400:
                    status_item.setForeground(QColor(COLORS['warning']))
                elif code >= 400:
                    status_item.setForeground(QColor(COLORS['danger']))
            except:
                pass
        self.history_table.setItem(row, 4, status_item)
        
        intercept_item = QTableWidgetItem("是" if intercepted.intercepted else "否")
        self.history_table.setItem(row, 5, intercept_item)
        
        self.history_table.scrollToBottom()
        
        # 【修复】自动对新行应用过滤规则
        self._apply_filter_to_row(row, intercepted)
        
        # 更新过滤统计
        self._update_filter_stats()
    
    def _apply_filter_to_row(self, row: int, intercepted: InterceptedFlow):
        """【新增】对指定行应用过滤规则"""
        filter_text = getattr(self, 'filter_rules', '').strip()
        if not filter_text:
            return
        
        # 解析过滤规则
        user_excluded_domains = []
        user_excluded_paths = []
        user_excluded_methods = []
        user_excluded_body = []
        
        lines = filter_text.split('\n')
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            
            line_lower = line.lower()
            
            if line_lower.startswith('domain:'):
                val = line.split(':', 1)[-1].strip().strip('"\'')
                if val:
                    user_excluded_domains.append(val.lower())
            elif line_lower.startswith('path:'):
                val = line.split(':', 1)[-1].strip().strip('"\'')
                if val:
                    user_excluded_paths.append(val.lower())
            elif line_lower.startswith('method:'):
                val = line.split(':', 1)[-1].strip().strip('"\'')
                if val:
                    user_excluded_methods.append(val.upper())
            elif line_lower.startswith('body:'):
                val = line.split(':', 1)[-1].strip().strip('"\'')
                if val:
                    user_excluded_body.append(val.lower())
            else:
                if line.startswith('.'):
                    user_excluded_paths.append(line.lower())
                elif line.startswith('/'):
                    user_excluded_paths.append(line.lower())
                elif line.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'PATCH']:
                    user_excluded_methods.append(line.upper())
                elif '.' in line:
                    user_excluded_domains.append(line.lower())
                else:
                    user_excluded_body.append(line.lower())
        
        # 检查当前行是否应该隐藏
        url = intercepted.url.lower()
        method = intercepted.method.upper()
        host = intercepted.host.lower()
        path = url.split('?')[0] if '?' in url else url
        body = intercepted.content.decode('utf-8', errors='ignore').lower() if intercepted.content else ''
        
        should_hide = False
        
        for domain in user_excluded_domains:
            if domain in host:
                should_hide = True
                break
        
        if not should_hide:
            for p in user_excluded_paths:
                if p in path or p in url:
                    should_hide = True
                    break
        
        if not should_hide:
            for m in user_excluded_methods:
                if m == method:
                    should_hide = True
                    break
        
        if not should_hide and body:
            for b in user_excluded_body:
                if b in body:
                    should_hide = True
                    break
        
        self.history_table.setRowHidden(row, should_hide)
    
    def update_request(self, intercepted: InterceptedFlow):
        """更新请求状态 - 修复响应显示问题"""
        for row in range(self.history_table.rowCount()):
            id_item = self.history_table.item(row, 0)
            if id_item and str(id_item.text()) == str(intercepted.id):
                # 更新状态码
                status_code = intercepted.status_code
                status_item = QTableWidgetItem(str(status_code))
                try:
                    if status_code != '-' and status_code != '无响应':
                        code = int(status_code)
                        if 200 <= code < 300:
                            status_item.setForeground(QColor(COLORS['success']))
                        elif 300 <= code < 400:
                            status_item.setForeground(QColor(COLORS['warning']))
                        elif code >= 400:
                            status_item.setForeground(QColor(COLORS['danger']))
                except:
                    pass
                self.history_table.setItem(row, 4, status_item)
                # 【关键修复】更新存储的数据，包含响应信息
                id_item.setData(Qt.UserRole, intercepted)
                # 如果当前选中的是这一行，更新详情显示
                if self.history_table.currentRow() == row:
                    self._show_request_detail(intercepted)
                break
    
    def clear_history(self):
        """【修复】清除历史 - 添加统计更新"""
        self.history.clear()
        self.history_table.setRowCount(0)
        self.req_detail.clear()
        self.res_detail.clear()
        # 【修复】更新统计标签
        self._update_filter_stats()
    
    def _on_item_selected(self, item):
        """选中历史项"""
        row = item.row()
        if row < len(self.history):
            req = self.history[row]
            self._show_request_detail(req)
    
    def _show_request_detail(self, req: InterceptedFlow):
        """显示请求详情"""
        req_text = f"{req.method} {req.url} HTTP/1.1\n"
        for k, v in req.headers.items():
            req_text += f"{k}: {v}\n"
        if req.content:
            req_text += "\n"
            try:
                req_text += req.content.decode('utf-8', errors='ignore')
            except:
                req_text += str(req.content)
        
        self.req_detail.setPlainText(req_text)
        
        if req.response_content:
            res_text = f"HTTP/1.1 {req.status_code}\n"
            for k, v in req.response_headers.items():
                res_text += f"{k}: {v}\n"
            res_text += "\n"
            try:
                res_text += req.response_content.decode('utf-8', errors='ignore')
            except:
                res_text += str(req.response_content)
            self.res_detail.setPlainText(res_text)
        else:
            self.res_detail.setPlainText("(等待响应...)")
    
    def _on_context_menu(self, pos):
        """右键菜单"""
        menu = QMenu(self)
        
        send_rep_action = menu.addAction("发送到 Repeater")
        send_int_action = menu.addAction("发送到 Intruder")
        menu.addSeparator()
        clear_action = menu.addAction("清空历史记录")
        
        action = menu.exec(self.history_table.mapToGlobal(pos))
        
        if action == send_rep_action:
            self._send_to_repeater()
        elif action == send_int_action:
            self._send_to_intruder()
        elif action == clear_action:
            self.clear_history()
    
    def _send_to_repeater(self):
        """发送到Repeater"""
        row = self.history_table.currentRow()
        if row >= 0 and row < len(self.history):
            req = self.history[row]
            self.send_to_repeater.emit(req.to_dict())
    
    def _send_to_intruder(self):
        """发送到Intruder"""
        row = self.history_table.currentRow()
        if row >= 0 and row < len(self.history):
            req = self.history[row]
            self.send_to_intruder.emit(req.to_dict())
    
    def _open_filter_dialog(self):
        """【新增】打开过滤配置对话框"""
        dialog = QDialog(self)
        dialog.setWindowTitle("配置过滤规则")
        dialog.setMinimumWidth(450)
        dialog.setMinimumHeight(400)
        
        layout = QVBoxLayout(dialog)
        layout.setSpacing(15)
        
        # 说明标签
        help_label = QLabel("每行一个排除条件，支持以下格式:\n"
                           "• 域名: freebuf.com, jd.com\n"
                           "• 路径: .css, .js, .png, /api/\n"
                           "• 方法: GET, POST\n"
                           "• Body内容: 任意字符串")
        help_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        layout.addWidget(help_label)
        
        # 过滤规则输入框
        filter_edit = QDialogTextEdit()
        filter_edit.setPlainText(self.filter_rules)
        filter_edit.setPlaceholderText("# 每行一个排除条件\n"
                                       "# 域名排除\n"
                                       "freebuf.com\n"
                                       "jd.com\n\n"
                                       "# 路径排除\n"
                                       ".css\n"
                                       ".js\n"
                                       ".png")
        filter_edit.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['bg_secondary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                padding: 10px;
                border-radius: 4px;
                font-family: Consolas, monospace;
                font-size: 12px;
            }}
        """)
        layout.addWidget(filter_edit)
        
        # 按钮
        btn_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btn_box.accepted.connect(dialog.accept)
        btn_box.rejected.connect(dialog.reject)
        
        # 样式
        btn_box.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['accent']};
                color: white;
                border: none;
                padding: 8px 20px;
                border-radius: 4px;
                min-width: 80px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent_hover']};
            }}
        """)
        layout.addWidget(btn_box)
        
        # 应用样式
        dialog.setStyleSheet(f"""
            QDialog {{
                background-color: {COLORS['bg_primary']};
            }}
        """)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.filter_rules = filter_edit.toPlainText()
            self._do_apply_filter()
            self._save_filter_config()
    
    def _save_filter_config(self):
        """【修复】保存过滤配置"""
        if self.config_manager:
            self.config_manager.set_filter_config(
                True,  # 过滤始终启用
                getattr(self, 'filter_rules', '')
            )
            self.config_manager.save()
    
    def _apply_filter(self):
        """【修复】应用过滤 - 直接执行，不使用防抖"""
        self._do_apply_filter()
    
    def _do_apply_filter(self):
        """【修复】实际执行过滤逻辑 - 简化处理避免卡顿"""
        filter_text = getattr(self, 'filter_rules', '').strip()
        
        # 如果没有过滤规则，显示所有行
        if not filter_text:
            for row in range(self.history_table.rowCount()):
                self.history_table.setRowHidden(row, False)
            # 更新统计
            self._update_filter_stats()
            return
        
        # 解析用户自定义过滤规则
        user_excluded_domains = []
        user_excluded_paths = []
        user_excluded_methods = []
        user_excluded_body = []
        
        lines = filter_text.split('\n')
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            
            # 【修复】优化规则解析逻辑
            line_lower = line.lower()
            
            # 域名排除 - 包含.且不以/开头，或者是显式的domain:xxx
            if line_lower.startswith('domain:'):
                val = line.split(':', 1)[-1].strip().strip('"\'')
                if val:
                    user_excluded_domains.append(val.lower())
            # 路径排除 - 以.或/开头，或者是显式的path:xxx
            elif line_lower.startswith('path:'):
                val = line.split(':', 1)[-1].strip().strip('"\'')
                if val:
                    user_excluded_paths.append(val.lower())
            # 方法排除
            elif line_lower.startswith('method:'):
                val = line.split(':', 1)[-1].strip().strip('"\'')
                if val:
                    user_excluded_methods.append(val.upper())
            # Body排除
            elif line_lower.startswith('body:'):
                val = line.split(':', 1)[-1].strip().strip('"\'')
                if val:
                    user_excluded_body.append(val.lower())
            # 自动判断
            else:
                # 以.开头的是路径/后缀
                if line.startswith('.'):
                    user_excluded_paths.append(line.lower())
                # 以/开头的是路径
                elif line.startswith('/'):
                    user_excluded_paths.append(line.lower())
                # 大写的方法是HTTP方法
                elif line.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'PATCH']:
                    user_excluded_methods.append(line.upper())
                # 包含.的是域名
                elif '.' in line:
                    user_excluded_domains.append(line.lower())
                # 其他作为body排除
                else:
                    user_excluded_body.append(line.lower())
        
        for row in range(self.history_table.rowCount()):
            id_item = self.history_table.item(row, 0)
            if not id_item:
                continue
            
            intercepted = id_item.data(Qt.UserRole)
            if not intercepted:
                continue
            
            url = intercepted.url.lower()
            method = intercepted.method.upper()
            host = intercepted.host.lower()
            path = url.split('?')[0] if '?' in url else url
            body = intercepted.content.decode('utf-8', errors='ignore').lower() if intercepted.content else ''
            
            should_hide = False
            
            # 应用用户自定义域名排除
            for domain in user_excluded_domains:
                if domain in host:
                    should_hide = True
                    break
            
            # 应用用户自定义路径排除
            if not should_hide:
                for p in user_excluded_paths:
                    if p in path or p in url:
                        should_hide = True
                        break
            
            # 应用用户自定义方法排除
            if not should_hide:
                for m in user_excluded_methods:
                    if m == method:
                        should_hide = True
                        break
            
            # 应用用户自定义Body排除
            if not should_hide and body:
                for b in user_excluded_body:
                    if b in body:
                        should_hide = True
                        break
            
            # 设置行隐藏/显示
            self.history_table.setRowHidden(row, should_hide)
        
        # 更新过滤统计
        self._update_filter_stats()
        
        # 保存配置
        self._save_filter_config()
    
    def _update_filter_stats(self):
        """【修复】更新过滤统计信息"""
        total = self.history_table.rowCount()
        visible = 0
        for row in range(total):
            if not self.history_table.isRowHidden(row):
                visible += 1
        
        self.filter_stats_label.setText(f"已显示 {visible} / 总计 {total} 条")
        
        # 【修复】根据是否有过滤规则和过滤效果调整颜色
        has_filters = bool(getattr(self, 'filter_rules', '').strip())
        if has_filters and visible < total:
            self.filter_stats_label.setStyleSheet(f"color: {COLORS['accent']}; font-size: 11px;")
        else:
            self.filter_stats_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px;")
    
    def load_filter_config(self):
        """【修复】加载过滤配置"""
        if not self.config_manager:
            return
        
        filter_config = self.config_manager.get_filter_config()
        self.filter_rules = filter_config.get('rules', '')
        
        # 应用过滤
        self._do_apply_filter()


class ProxyInterceptTab(QWidget):
    """代理拦截标签页"""
    
    send_to_repeater = Signal(object)
    send_to_intruder = Signal(object)
    
    def __init__(self, proxy_thread: 'ProxyThread' = None):
        super().__init__()
        self.proxy_thread = proxy_thread
        self.intercepted_list = []
        self.current_flow_id = None
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        # 拦截控制栏
        control_layout = QHBoxLayout()
        
        self.forward_btn = QPushButton("放行 (Forward)")
        self.forward_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['success']};
                color: white;
                border: none;
                padding: 8px 20px;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #059669;
            }}
            QPushButton:disabled {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_secondary']};
            }}
        """)
        self.forward_btn.setEnabled(False)
        self.forward_btn.clicked.connect(self._forward)
        control_layout.addWidget(self.forward_btn)
        
        self.drop_btn = QPushButton("丢弃 (Drop)")
        self.drop_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['danger']};
                color: white;
                border: none;
                padding: 8px 20px;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #dc2626;
            }}
            QPushButton:disabled {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_secondary']};
            }}
        """)
        self.drop_btn.setEnabled(False)
        self.drop_btn.clicked.connect(self._drop)
        control_layout.addWidget(self.drop_btn)
        
        # 【新增】放行全部按钮
        self.forward_all_btn = QPushButton("放行全部")
        self.forward_all_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['info']};
                color: white;
                border: none;
                padding: 8px 20px;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #0284c7;
            }}
            QPushButton:disabled {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_secondary']};
            }}
        """)
        self.forward_all_btn.setEnabled(False)
        self.forward_all_btn.clicked.connect(self._forward_all)
        control_layout.addWidget(self.forward_all_btn)
        
        control_layout.addStretch()
        
        # 【新增】发送到模块按钮
        send_layout = QHBoxLayout()
        send_layout.setSpacing(8)
        
        to_repeater_btn = QPushButton("发送到 Repeater")
        to_repeater_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['accent']};
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent_hover']};
            }}
        """)
        to_repeater_btn.clicked.connect(self._send_to_repeater)
        send_layout.addWidget(to_repeater_btn)
        
        to_intruder_btn = QPushButton("发送到 Intruder")
        to_intruder_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['warning']};
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #d97706;
            }}
        """)
        to_intruder_btn.clicked.connect(self._send_to_intruder)
        send_layout.addWidget(to_intruder_btn)
        
        control_layout.addLayout(send_layout)
        
        layout.addLayout(control_layout)
        
        # 分割器
        splitter = QSplitter(Qt.Vertical)
        splitter.setHandleWidth(6)
        splitter.setStyleSheet(f"""
            QSplitter::handle {{
                background-color: {COLORS['border']};
            }}
            QSplitter::handle:hover {{
                background-color: {COLORS['accent']};
            }}
        """)
        
        # 拦截列表
        list_widget = QWidget()
        list_layout = QVBoxLayout(list_widget)
        list_layout.setContentsMargins(0, 0, 0, 0)
        
        list_label = QLabel("拦截列表")
        list_label.setStyleSheet(f"font-weight: bold; color: {COLORS['accent']}; font-size: 14px;")
        list_layout.addWidget(list_label)
        
        self.intercept_table = QTableWidget()
        self.intercept_table.setColumnCount(4)
        self.intercept_table.setHorizontalHeaderLabels(["ID", "时间", "方法", "URL"])
        self.intercept_table.setColumnWidth(0, 50)
        self.intercept_table.setColumnWidth(1, 70)
        self.intercept_table.setColumnWidth(2, 60)
        
        header = self.intercept_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        
        self.intercept_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.intercept_table.setAlternatingRowColors(True)
        self.intercept_table.setEditTriggers(QTableWidget.NoEditTriggers)  # 【修复】禁用编辑，防止双击进入编辑模式
        self.intercept_table.itemClicked.connect(self._on_item_selected)
        # 启用右键菜单
        self.intercept_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.intercept_table.customContextMenuRequested.connect(self._on_context_menu)
        
        # 【修复】添加行高和选中样式优化 - 移除选中边框避免覆盖URL
        self.intercept_table.verticalHeader().setDefaultSectionSize(28)
        self.intercept_table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLORS['bg_secondary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                gridline-color: {COLORS['border']};
            }}
            QTableWidget::item {{
                padding: 4px 8px;
                border: none;
            }}
            QTableWidget::item:selected {{
                background-color: {COLORS['accent']};
                color: white;
                border: none;
                outline: none;
            }}
            QHeaderView::section {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_primary']};
                padding: 8px;
                border: none;
                border-right: 1px solid {COLORS['border']};
                border-bottom: 1px solid {COLORS['border']};
                font-weight: bold;
            }}
        """)
        
        list_layout.addWidget(self.intercept_table)
        
        splitter.addWidget(list_widget)
        
        # 请求详情（可编辑）
        detail_widget = QWidget()
        detail_layout = QVBoxLayout(detail_widget)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        
        detail_label = QLabel("请求详情 (可编辑后放行)")
        detail_label.setStyleSheet(f"font-weight: bold; color: {COLORS['accent']}; font-size: 14px;")
        detail_layout.addWidget(detail_label)
        
        self.request_edit = QPlainTextEdit()
        self.request_edit.setFont(QFont("Consolas", 10))
        self.highlighter = HTTPHighlighter(self.request_edit.document(), is_request=True)
        detail_layout.addWidget(self.request_edit)
        
        splitter.addWidget(detail_widget)
        
        splitter.setSizes([200, 400])
        
        layout.addWidget(splitter)
    
    def add_intercepted(self, intercepted: InterceptedFlow):
        """添加拦截请求"""
        self.intercepted_list.append(intercepted)
        
        row = self.intercept_table.rowCount()
        self.intercept_table.insertRow(row)
        
        id_item = QTableWidgetItem(str(intercepted.id))
        id_item.setData(Qt.UserRole, intercepted)
        self.intercept_table.setItem(row, 0, id_item)
        
        self.intercept_table.setItem(row, 1, QTableWidgetItem(intercepted.timestamp))
        self.intercept_table.setItem(row, 2, QTableWidgetItem(intercepted.method))
        
        url_item = QTableWidgetItem(intercepted.url[:80])
        url_item.setToolTip(intercepted.url)
        self.intercept_table.setItem(row, 3, url_item)
        
        # 自动选中
        self.intercept_table.selectRow(row)
        self._on_item_selected(self.intercept_table.item(row, 0))
        
        # 【新增】启用放行全部按钮
        self.forward_all_btn.setEnabled(True)
    
    def _on_item_selected(self, item):
        """选中拦截项"""
        row = item.row()
        if row < len(self.intercepted_list):
            intercepted = self.intercepted_list[row]
            self.current_flow_id = intercepted.id
            
            req_text = f"{intercepted.method} {intercepted.url} HTTP/1.1\n"
            for k, v in intercepted.headers.items():
                req_text += f"{k}: {v}\n"
            if intercepted.content:
                req_text += "\n"
                try:
                    req_text += intercepted.content.decode('utf-8', errors='ignore')
                except:
                    req_text += str(intercepted.content)
            
            self.request_edit.setPlainText(req_text)
            
            if not intercepted.released:
                self.forward_btn.setEnabled(True)
                self.drop_btn.setEnabled(True)
            else:
                self.forward_btn.setEnabled(False)
                self.drop_btn.setEnabled(False)
    
    def _on_context_menu(self, pos):
        """右键菜单"""
        menu = QMenu(self)
        
        send_rep_action = menu.addAction("发送到 Repeater")
        send_int_action = menu.addAction("发送到 Intruder")
        menu.addSeparator()
        forward_action = menu.addAction("放行 (Forward)")
        drop_action = menu.addAction("丢弃 (Drop)")
        
        action = menu.exec(self.intercept_table.mapToGlobal(pos))
        
        if action == send_rep_action:
            self._send_to_repeater()
        elif action == send_int_action:
            self._send_to_intruder()
        elif action == forward_action:
            self._forward()
        elif action == drop_action:
            self._drop()
    
    def _send_to_repeater(self):
        """发送到 Repeater"""
        row = self.intercept_table.currentRow()
        if row >= 0 and row < len(self.intercepted_list):
            req = self.intercepted_list[row]
            self.send_to_repeater.emit(req.to_dict())
    
    def _send_to_intruder(self):
        """发送到 Intruder"""
        row = self.intercept_table.currentRow()
        if row >= 0 and row < len(self.intercepted_list):
            req = self.intercepted_list[row]
            self.send_to_intruder.emit(req.to_dict())
    
    def _forward(self):
        """放行请求 - 【修复】自动选择下一个请求"""
        if self.current_flow_id and self.proxy_thread:
            modified_text = self.request_edit.toPlainText()
            
            try:
                lines = modified_text.split('\n')
                body_start = 0
                for i, line in enumerate(lines[1:], 1):
                    if line.strip() == '':
                        body_start = i + 1
                        break
                
                body = '\n'.join(lines[body_start:]) if body_start > 0 else ''
                modified_content = body.encode('utf-8') if body else None
            except:
                modified_content = None
            
            self.proxy_thread.forward_request(self.current_flow_id, modified_content)
            
            # 从列表中移除并获取当前行号
            removed_row = -1
            for i, intercepted in enumerate(self.intercepted_list):
                if intercepted.id == self.current_flow_id:
                    intercepted.released = True
                    removed_row = i
                    self.intercept_table.removeRow(i)
                    self.intercepted_list.pop(i)
                    break
            
            # 【关键修复】自动选择下一个请求
            if self.intercepted_list:
                # 选择下一个请求（如果存在）
                next_row = min(removed_row, len(self.intercepted_list) - 1)
                if next_row >= 0:
                    self.intercept_table.selectRow(next_row)
                    self._on_item_selected(self.intercept_table.item(next_row, 0))
            else:
                # 没有更多请求，清空编辑区
                self.request_edit.clear()
                self.current_flow_id = None
                self.forward_btn.setEnabled(False)
                self.drop_btn.setEnabled(False)
                self.forward_all_btn.setEnabled(False)
    
    def _drop(self):
        """丢弃请求 - 【修复】自动选择下一个请求"""
        if self.current_flow_id and self.proxy_thread:
            self.proxy_thread.drop_request(self.current_flow_id)
            
            # 从列表中移除并获取当前行号
            removed_row = -1
            for i, intercepted in enumerate(self.intercepted_list):
                if intercepted.id == self.current_flow_id:
                    intercepted.dropped = True
                    intercepted.released = True
                    removed_row = i
                    self.intercept_table.removeRow(i)
                    self.intercepted_list.pop(i)
                    break
            
            # 【关键修复】自动选择下一个请求
            if self.intercepted_list:
                # 选择下一个请求（如果存在）
                next_row = min(removed_row, len(self.intercepted_list) - 1)
                if next_row >= 0:
                    self.intercept_table.selectRow(next_row)
                    self._on_item_selected(self.intercept_table.item(next_row, 0))
            else:
                # 没有更多请求，清空编辑区
                self.request_edit.clear()
                self.current_flow_id = None
                self.forward_btn.setEnabled(False)
                self.drop_btn.setEnabled(False)
                self.forward_all_btn.setEnabled(False)
    
    def _forward_all(self):
        """【新增】放行所有拦截的请求"""
        if not self.proxy_thread:
            return
        
        # 复制列表避免遍历时修改
        flows_to_forward = [f for f in self.intercepted_list if not f.released]
        
        for intercepted in flows_to_forward:
            # 获取当前行
            row = -1
            for i, f in enumerate(self.intercepted_list):
                if f.id == intercepted.id:
                    row = i
                    break
            
            if row >= 0:
                # 使用原始内容直接放行
                self.proxy_thread.forward_request(intercepted.id, None)
                intercepted.released = True
                self.intercept_table.removeRow(row)
                self.intercepted_list.pop(row)
        
        # 清空编辑区
        self.request_edit.clear()
        self.current_flow_id = None
        self.forward_btn.setEnabled(False)
        self.drop_btn.setEnabled(False)
        self.forward_all_btn.setEnabled(False)
    
    def clear_intercepted(self):
        """【新增】清空所有拦截的请求"""
        # 丢弃所有未释放的请求
        for intercepted in self.intercepted_list:
            if not intercepted.released and self.proxy_thread:
                self.proxy_thread.drop_request(intercepted.id)
        
        # 清空列表和表格
        self.intercepted_list.clear()
        self.intercept_table.setRowCount(0)
        self.request_edit.clear()
        self.current_flow_id = None
        self.forward_btn.setEnabled(False)
        self.drop_btn.setEnabled(False)
        self.forward_all_btn.setEnabled(False)


class ProxyWidget(QWidget):
    """代理主界面"""
    
    send_to_repeater = Signal(object)
    send_to_intruder = Signal(object)
    
    def __init__(self):
        super().__init__()
        self.proxy_thread = None
        self._is_toggling = False  # 【修复】防止重复点击的标志
        # 初始化配置管理器
        self.config_manager = ConfigManager()
        self.init_ui()
        # 加载配置
        self._load_config()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        # 控制栏
        control_layout = QHBoxLayout()
        control_layout.setSpacing(10)
        
        control_layout.addWidget(QLabel("代理地址:"))
        self.host_input = QLineEdit("127.0.0.1")
        self.host_input.setFixedWidth(120)
        self.host_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: {COLORS['bg_secondary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                padding: 5px;
                border-radius: 4px;
            }}
        """)
        control_layout.addWidget(self.host_input)
        
        control_layout.addWidget(QLabel("端口:"))
        self.port_input = QLineEdit("8080")
        self.port_input.setFixedWidth(80)
        self.port_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: {COLORS['bg_secondary']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                padding: 5px;
                border-radius: 4px;
            }}
        """)
        control_layout.addWidget(self.port_input)
        
        self.start_btn = QPushButton("启动代理")
        self.start_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['success']};
                color: white;
                border: none;
                padding: 8px 20px;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #059669;
            }}
        """)
        self.start_btn.clicked.connect(self._toggle_proxy)
        control_layout.addWidget(self.start_btn)
        
        self.intercept_cb = QCheckBox("拦截请求")
        self.intercept_cb.setChecked(True)
        self.intercept_cb.setStyleSheet(f"color: {COLORS['text_primary']};")
        self.intercept_cb.stateChanged.connect(self._on_intercept_changed)
        control_layout.addWidget(self.intercept_cb)
        
        control_layout.addStretch()
        
        layout.addLayout(control_layout)
        
        # 状态栏
        self.status_label = QLabel("代理未启动")
        self.status_label.setStyleSheet(f"color: {COLORS['text_secondary']}; padding: 5px;")
        layout.addWidget(self.status_label)
        
        # 检查 mitmproxy 是否安装
        if not MITMPROXY_AVAILABLE:
            warning_label = QLabel("警告: mitmproxy 未安装，请运行: pip install mitmproxy")
            warning_label.setStyleSheet(f"color: {COLORS['danger']}; padding: 5px; font-weight: bold;")
            layout.addWidget(warning_label)
        
        # 子标签页
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(f"""
            QTabWidget::pane {{
                border: 1px solid {COLORS['border']};
                background-color: {COLORS['bg_secondary']};
            }}
            QTabBar::tab {{
                background-color: {COLORS['bg_tertiary']};
                color: {COLORS['text_secondary']};
                padding: 8px 16px;
                margin-right: 2px;
            }}
            QTabBar::tab:selected {{
                background-color: {COLORS['accent']};
                color: white;
            }}
        """)
        
        # 拦截标签
        self.intercept_tab = ProxyInterceptTab(None)
        self.intercept_tab.send_to_repeater.connect(self._on_send_to_repeater)
        self.intercept_tab.send_to_intruder.connect(self._on_send_to_intruder)
        self.tabs.addTab(self.intercept_tab, "拦截")
        
        # 历史标签 - 传入配置管理器
        self.history_tab = ProxyHistoryTab(None, self.config_manager)
        self.history_tab.send_to_repeater.connect(self._on_send_to_repeater)
        self.history_tab.send_to_intruder.connect(self._on_send_to_intruder)
        self.tabs.addTab(self.history_tab, "历史")
        
        layout.addWidget(self.tabs)
        
        # 提示
        tip_label = QLabel(
            "提示: 1. 将浏览器代理设置为 127.0.0.1:8080\n"
            "     2. 首次使用 HTTPS 需要安装 mitmproxy 证书\n"
            "     3. 访问 http://mitm.it 下载证书并安装到'受信任的根证书颁发机构'\n"
            "     4. 开启拦截后，HTTP请求会被暂停等待放行\n"
            "     5. 【重要】抓取localhost/127.0.0.1需要浏览器特殊配置，详见关于页面"
        )
        tip_label.setStyleSheet(f"color: {COLORS['text_secondary']}; padding: 5px; font-size: 12px;")
        layout.addWidget(tip_label)
    
    def _toggle_proxy(self):
        """启动/停止代理"""
        if not MITMPROXY_AVAILABLE:
            QMessageBox.warning(self, "警告", "mitmproxy 未安装，请先运行: pip install mitmproxy")
            return
        
        # 【修复】防止重复点击
        if self._is_toggling:
            return
        self._is_toggling = True
        self.start_btn.setEnabled(False)
        
        try:
            if self.proxy_thread and self.proxy_thread._running:
                # 停止代理
                self.proxy_thread.stop()
                # 【修复】使用更长的等待时间，确保线程完全结束
                if not self.proxy_thread.wait(5000):  # 等待最多5秒
                    print("警告: 代理线程未在5秒内结束")
                self.proxy_thread = None
                
                self.start_btn.setText("启动代理")
                self.start_btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {COLORS['success']};
                        color: white;
                        border: none;
                        padding: 8px 20px;
                        border-radius: 4px;
                        font-weight: bold;
                    }}
                    QPushButton:hover {{
                        background-color: #059669;
                    }}
                """)
                self.status_label.setText("代理未启动")
                self.status_label.setStyleSheet(f"color: {COLORS['text_secondary']}; padding: 5px;")
                
                # 更新标签页
                self.intercept_tab.proxy_thread = None
                self.history_tab.proxy_thread = None
                
                # 【修复】清空拦截列表
                self.intercept_tab.clear_intercepted()
                
                # 保存配置
                self._save_config()
            else:
                # 【修复】确保旧线程已经完全结束
                if self.proxy_thread:
                    self.proxy_thread.stop()
                    # 等待旧线程结束（最多5秒）
                    if self.proxy_thread.isRunning():
                        self.proxy_thread.wait(5000)
                    # 【修复】强制终止如果还在运行
                    if self.proxy_thread.isRunning():
                        self.proxy_thread.terminate()
                        self.proxy_thread.wait(1000)
                    self.proxy_thread = None
                    # 【修复】等待更长时间确保端口释放
                    import time
                    time.sleep(1.0)
                
                # 启动代理
                try:
                    host = self.host_input.text() or "127.0.0.1"
                    port = int(self.port_input.text() or 8080)
                    
                    self.proxy_thread = ProxyThread(host, port)
                    self.proxy_thread.signals.request_intercepted.connect(self._on_intercepted)
                    self.proxy_thread.signals.request_logged.connect(self._on_logged)
                    self.proxy_thread.signals.response_received.connect(self._on_response)
                    self.proxy_thread.signals.status_changed.connect(self._on_status_changed)
                    self.proxy_thread.set_intercept(self.intercept_cb.isChecked())
                    self.proxy_thread.start()
                    
                    self.start_btn.setText("停止代理")
                    self.start_btn.setStyleSheet(f"""
                        QPushButton {{
                            background-color: {COLORS['danger']};
                            color: white;
                            border: none;
                            padding: 8px 20px;
                            border-radius: 4px;
                            font-weight: bold;
                        }}
                        QPushButton:hover {{
                            background-color: #dc2626;
                        }}
                    """)
                    
                    # 更新标签页
                    self.intercept_tab.proxy_thread = self.proxy_thread
                    self.history_tab.proxy_thread = self.proxy_thread
                    
                except Exception as e:
                    self.status_label.setText(f"启动失败: {str(e)}")
                    self.status_label.setStyleSheet(f"color: {COLORS['danger']}; padding: 5px;")
                    QMessageBox.critical(self, "错误", f"启动代理失败: {str(e)}")
                finally:
                    # 保存配置
                    self._save_config()
        finally:
            # 【修复】恢复按钮状态
            self._is_toggling = False
            self.start_btn.setEnabled(True)

    def stop_proxy(self):
        """外部调用：停止代理线程"""
        if self.proxy_thread and self.proxy_thread._running:
            self.proxy_thread.stop()
            if self.proxy_thread.isRunning():
                self.proxy_thread.wait(3000)
        
        # 【方案A修复】停止后清理引用，确保下次启动创建新实例
        import time
        time.sleep(0.5)
        self.proxy_thread = None
        
        # 更新标签页的引用
        self.intercept_tab.proxy_thread = None
        self.history_tab.proxy_thread = None

    def _on_intercept_changed(self, state):
        """拦截状态改变"""
        if self.proxy_thread:
            self.proxy_thread.set_intercept(state == Qt.Checked)
    
    def _on_status_changed(self, status):
        """状态改变"""
        self.status_label.setText(status)
        if "运行中" in status:
            self.status_label.setStyleSheet(f"color: {COLORS['success']}; font-weight: bold; padding: 5px;")
        else:
            self.status_label.setStyleSheet(f"color: {COLORS['danger']}; padding: 5px;")
    
    def _on_intercepted(self, intercepted):
        """请求被拦截"""
        self.intercept_tab.add_intercepted(intercepted)
        self.history_tab.add_request(intercepted)
    
    def _on_logged(self, intercepted):
        """请求被记录"""
        self.history_tab.add_request(intercepted)
    
    def _on_response(self, intercepted, flow):
        """响应被记录"""
        self.history_tab.update_request(intercepted)
    
    def _on_send_to_repeater(self, request_data):
        """发送到Repeater"""
        self.send_to_repeater.emit(request_data)
    
    def _on_send_to_intruder(self, request_data):
        """发送到Intruder"""
        self.send_to_intruder.emit(request_data)
    
    def _load_config(self):
        """【新增】加载配置"""
        if not self.config_manager:
            return
        
        # 加载代理配置
        proxy_config = self.config_manager.get_proxy_config()
        self.host_input.setText(proxy_config.get('host', '127.0.0.1'))
        self.port_input.setText(str(proxy_config.get('port', 8080)))
        self.intercept_cb.setChecked(proxy_config.get('intercept', True))
        
        # 加载过滤配置
        self.history_tab.load_filter_config()
    
    def _save_config(self):
        """【新增】保存配置"""
        if not self.config_manager:
            return
        
        # 保存代理配置
        try:
            port = int(self.port_input.text() or 8080)
        except:
            port = 8080
        
        self.config_manager.set_proxy_config(
            self.host_input.text() or '127.0.0.1',
            port,
            self.intercept_cb.isChecked()
        )
        
        # 保存过滤配置（在历史标签中自动保存）
        
        self.config_manager.save()
