#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
异步HTTP客户端 - 使用httpx
支持流量日志记录 - 显示完整请求/响应内容
"""

import httpx
from typing import Dict, Optional, Any, Callable
from datetime import datetime

from .models import TrafficLog


DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
DEFAULT_TIMEOUT = 30


class AsyncHTTPClient:
    """异步HTTP客户端"""
    
    def __init__(self, 
                 proxies: Optional[Dict] = None, 
                 headers: Optional[Dict] = None, 
                 cookies: Optional[Dict] = None,
                 timeout: int = DEFAULT_TIMEOUT):
        
        self.proxies = proxies
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.log_callback: Optional[Callable[[TrafficLog], None]] = None
        self.request_counter = 0
        
        # 存储请求体用于日志
        self._last_request_body = b""
        
        # 确保User-Agent已设置
        if "User-Agent" not in self.headers:
            self.headers["User-Agent"] = DEFAULT_USER_AGENT
        
        # 创建httpx客户端
        try:
            self.client = httpx.AsyncClient(
                headers=self.headers,
                cookies=self.cookies,
                timeout=timeout,
                verify=False,
                trust_env=False
            )
            if proxies:
                for scheme, proxy_url in proxies.items():
                    if hasattr(self.client, '_mounts'):
                        self.client._mounts[scheme] = httpx.HTTPTransport(proxy=proxy_url)
        except:
            self.client = httpx.AsyncClient(
                proxies=proxies,
                headers=self.headers,
                cookies=self.cookies,
                timeout=timeout,
                verify=False,
                trust_env=False
            )
    
    def set_log_callback(self, callback: Callable[[TrafficLog], None]):
        """设置流量日志回调"""
        self.log_callback = callback
    
    def _format_request_body(self, content: bytes) -> str:
        """格式化请求体 - 尝试多种解码方式，显示完整内容"""
        if not content:
            return ""
        
        # 尝试UTF-8解码
        try:
            decoded = content.decode('utf-8')
            return decoded
        except:
            pass
        
        # 尝试Latin-1解码（不会失败）
        try:
            decoded = content.decode('latin-1')
            return decoded
        except:
            pass
        
        # 尝试GBK解码
        try:
            decoded = content.decode('gbk')
            return decoded
        except:
            pass
        
        # 作为十六进制显示（仅显示前2KB）
        if len(content) > 2048:
            hex_content = content[:2048].hex()
            return f"[Binary Content - {len(content)} bytes, showing first 2KB]\n{hex_content}\n... [truncated]"
        return content.hex()
    
    def _format_response_body(self, text: str, content: bytes) -> str:
        """格式化响应体 - 显示完整内容"""
        if text:
            # 返回完整文本内容
            return text
        
        # 尝试解码二进制内容
        if content:
            # 尝试UTF-8解码
            try:
                decoded = content.decode('utf-8')
                return decoded
            except:
                pass
            
            # 尝试Latin-1解码
            try:
                decoded = content.decode('latin-1')
                return decoded
            except:
                pass
            
            # 尝试GBK解码
            try:
                decoded = content.decode('gbk')
                return decoded
            except:
                pass
            
            # 作为十六进制显示（仅显示前5KB）
            if len(content) > 5120:
                hex_content = content[:5120].hex()
                return f"[Binary Content - {len(content)} bytes, showing first 5KB]\n{hex_content}\n... [truncated]"
            return content.hex()
        
        return ""
    
    def _log_traffic(self, response: httpx.Response, request_body: bytes = b""):
        """记录流量日志"""
        if self.log_callback:
            self.request_counter += 1
            
            # 格式化请求头
            req_headers = "\n".join([f"{k}: {v}" for k, v in response.request.headers.items()])
            res_headers = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
            
            # 处理请求体 - 显示完整内容
            req_body = self._format_request_body(request_body)
            
            # 处理响应体 - 显示完整内容
            res_body = self._format_response_body(response.text, response.content)
            
            log = TrafficLog(
                id=self.request_counter,
                timestamp=datetime.now().strftime("%H:%M:%S"),
                method=response.request.method,
                url=str(response.request.url),
                status_code=response.status_code,
                request_headers=req_headers,
                request_body=req_body,
                response_headers=res_headers,
                response_body=res_body
            )
            self.log_callback(log)
    
    async def upload_file(self, 
                          url: str, 
                          file_field_name: str, 
                          filename: str, 
                          file_content: bytes, 
                          content_type: str = "application/octet-stream",
                          extra_data: Optional[Dict] = None,
                          method: str = "POST") -> httpx.Response:
        """上传文件"""
        files = {
            file_field_name: (filename, file_content, content_type)
        }
        
        try:
            if method.upper() == "POST":
                # 构建multipart请求并捕获请求体
                response = await self.client.post(url, files=files, data=extra_data)
                
                # 手动构建请求体用于日志
                boundary = "----WebKitFormBoundary" + "UploadRanger"
                request_body_parts = []
                
                # 添加文件部分
                request_body_parts.append(f"--{boundary}\r\n".encode())
                request_body_parts.append(f'Content-Disposition: form-data; name="{file_field_name}"; filename="{filename}"\r\n'.encode())
                request_body_parts.append(f"Content-Type: {content_type}\r\n\r\n".encode())
                request_body_parts.append(file_content)
                request_body_parts.append(f"\r\n--{boundary}--\r\n".encode())
                
                request_body = b"".join(request_body_parts)
                
            elif method.upper() == "PUT":
                response = await self.client.put(url, content=file_content)
                request_body = file_content
            else:
                raise ValueError(f"不支持的HTTP方法: {method}")
            
            self._log_traffic(response, request_body)
            return response
        except Exception as e:
            raise Exception(f"请求失败: {str(e)}")
    
    async def get(self, url: str, **kwargs) -> httpx.Response:
        """GET请求"""
        try:
            response = await self.client.get(url, **kwargs)
            self._log_traffic(response)
            return response
        except Exception as e:
            raise Exception(f"GET请求失败: {str(e)}")
    
    async def post(self, url: str, **kwargs) -> httpx.Response:
        """POST请求"""
        try:
            response = await self.client.post(url, **kwargs)
            self._log_traffic(response)
            return response
        except Exception as e:
            raise Exception(f"POST请求失败: {str(e)}")
    
    async def check_file_existence(self, url: str) -> httpx.Response:
        """检查文件是否存在"""
        try:
            response = await self.client.get(url)
            self._log_traffic(response)
            return response
        except Exception as e:
            raise Exception(f"文件存在性检查失败: {str(e)}")
    
    async def close(self):
        """关闭客户端"""
        await self.client.aclose()
