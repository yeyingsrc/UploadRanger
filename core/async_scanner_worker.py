#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
异步扫描工作线程
"""

import asyncio
from PySide6.QtCore import QThread, Signal

from core.async_scanner import AsyncScanner
from core.models import ScanResult, VulnerabilityFinding, TrafficLog


class AsyncScannerWorker(QThread):
    """异步扫描工作线程"""
    
    finished = Signal(ScanResult)
    progress = Signal(str)  # 日志消息
    finding_found = Signal(VulnerabilityFinding)  # 发现漏洞
    result_found = Signal(dict)  # 发现结果（用于实时显示）
    traffic_log = Signal(TrafficLog)  # 流量日志
    progress_update = Signal(int, str)  # 进度百分比和消息
    
    def __init__(self, target_url, file_param, upload_dir, proxies, headers, cookies):
        super().__init__()
        self.target_url = target_url
        self.file_param = file_param
        self.upload_dir = upload_dir
        self.proxies = proxies
        self.headers = headers
        self.cookies = cookies
        self.scanner = AsyncScanner()
    
    def _on_log(self, message: str):
        """日志回调"""
        self.progress.emit(message)
    
    def _on_traffic(self, log: TrafficLog):
        """流量日志回调"""
        self.traffic_log.emit(log)
    
    def _on_finding(self, finding: VulnerabilityFinding):
        """漏洞发现回调"""
        self.finding_found.emit(finding)
    
    def _on_result(self, result: dict):
        """结果回调（用于实时显示所有结果）"""
        self.result_found.emit(result)
    
    def _on_progress(self, message: str, percent: int):
        """进度回调"""
        self.progress_update.emit(percent, message)
    
    def run(self):
        """运行扫描"""
        import sys
        
        loop = asyncio.new_event_loop()
        
        # Linux 环境使用 Selector
        if sys.platform.startswith('linux'):
            loop = asyncio.SelectorEventLoop()
        
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(self.scanner.scan(
                target_url=self.target_url,
                file_param=self.file_param,
                upload_dir=self.upload_dir,
                proxies=self.proxies,
                headers=self.headers,
                cookies=self.cookies,
                on_log_callback=self._on_log,
                on_traffic_callback=self._on_traffic,
                on_finding_callback=self._on_finding,
                on_result_callback=self._on_result,  # 新增：结果回调
                progress_callback=self._on_progress
            ))
            self.finished.emit(result)
        except Exception as e:
            self.progress.emit(f"扫描错误: {str(e)}")
            import traceback
            traceback.print_exc()
            # 返回空结果
            from datetime import datetime
            empty_result = ScanResult(target=self.target_url, start_time=datetime.now())
            self.finished.emit(empty_result)
        finally:
            if loop and not loop.is_closed():
                try:
                    loop.close()
                except Exception:
                    pass
    
    def stop(self):
        """停止扫描"""
        self.scanner.stop()
        self.wait(1000)
