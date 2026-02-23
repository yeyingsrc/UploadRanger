#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
代理服务器 - HTTP/HTTPS抓包代理
支持拦截请求并发送到Repeater/Intruder
"""

import asyncio
import socket
import ssl
from typing import Callable, Optional, Dict
from urllib.parse import urlparse
import threading


class ProxyServer:
    """HTTP/HTTPS代理服务器"""
    
    def __init__(self, host: str = '127.0.0.1', port: int = 8080):
        self.host = host
        self.port = port
        self.running = False
        self.server = None
        self.intercept_enabled = False
        
        # 回调函数
        self.on_request: Optional[Callable[[dict], None]] = None
        self.on_response: Optional[Callable[[dict], None]] = None
        self.on_intercept: Optional[Callable[[dict], bool]] = None  # 返回True表示拦截
    
    def set_callbacks(self, 
                      on_request: Optional[Callable[[dict], None]] = None,
                      on_response: Optional[Callable[[dict], None]] = None,
                      on_intercept: Optional[Callable[[dict], bool]] = None):
        """设置回调函数"""
        self.on_request = on_request
        self.on_response = on_response
        self.on_intercept = on_intercept
    
    def start(self):
        """启动代理服务器"""
        self.running = True
        thread = threading.Thread(target=self._run_server, daemon=True)
        thread.start()
        return thread
    
    def stop(self):
        """停止代理服务器"""
        self.running = False
        if self.server:
            self.server.close()
    
    def _run_server(self):
        """运行服务器"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        async def handle_client(reader, writer):
            try:
                # 读取请求行
                request_line = await reader.readline()
                if not request_line:
                    return
                
                request_line = request_line.decode('utf-8', errors='ignore').strip()
                parts = request_line.split()
                if len(parts) < 3:
                    return
                
                method, target, version = parts[0], parts[1], parts[2]
                
                # 读取请求头
                headers = {}
                while True:
                    line = await reader.readline()
                    if line == b'\r\n' or not line:
                        break
                    try:
                        key, value = line.decode('utf-8', errors='ignore').strip().split(':', 1)
                        headers[key.strip()] = value.strip()
                    except:
                        pass
                
                # 读取请求体
                body = b''
                if 'Content-Length' in headers:
                    content_length = int(headers['Content-Length'])
                    body = await reader.read(content_length)
                
                # 构建请求数据
                request_data = {
                    'method': method,
                    'url': target,
                    'headers': headers,
                    'body': body.decode('utf-8', errors='ignore') if body else ''
                }
                
                # 通知请求
                if self.on_request:
                    self.on_request(request_data)
                
                # 检查是否需要拦截
                if self.intercept_enabled and self.on_intercept:
                    if self.on_intercept(request_data):
                        # 拦截请求，不转发
                        writer.close()
                        return
                
                # 转发请求
                if method == 'CONNECT':
                    # HTTPS CONNECT
                    await self._handle_connect(reader, writer, target)
                else:
                    # HTTP请求
                    await self._handle_http(reader, writer, method, target, headers, body)
                    
            except Exception as e:
                print(f"Proxy error: {e}")
            finally:
                try:
                    writer.close()
                except:
                    pass
        
        self.server = asyncio.start_server(handle_client, self.host, self.port)
        loop.run_until_complete(self.server)
        loop.run_forever()
    
    async def _handle_connect(self, client_reader, client_writer, target):
        """处理HTTPS CONNECT请求"""
        try:
            host, port = target.split(':')
            port = int(port)
            
            # 连接到目标服务器
            server_reader, server_writer = await asyncio.open_connection(host, port)
            
            # 发送200 Connection established
            client_writer.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
            await client_writer.drain()
            
            # 双向转发数据
            async def forward(reader, writer):
                try:
                    while True:
                        data = await reader.read(8192)
                        if not data:
                            break
                        writer.write(data)
                        await writer.drain()
                except:
                    pass
            
            await asyncio.gather(
                forward(client_reader, server_writer),
                forward(server_reader, client_writer)
            )
            
        except Exception as e:
            print(f"CONNECT error: {e}")
    
    async def _handle_http(self, client_reader, client_writer, method, target, headers, body):
        """处理HTTP请求"""
        try:
            # 解析目标URL
            if target.startswith('http'):
                parsed = urlparse(target)
                host = parsed.hostname
                port = parsed.port or 80
                path = parsed.path or '/'
                if parsed.query:
                    path += '?' + parsed.query
            else:
                host = headers.get('Host', '').split(':')[0]
                port = 80
                path = target
            
            # 连接到目标服务器
            server_reader, server_writer = await asyncio.open_connection(host, port)
            
            # 构建请求
            request_line = f"{method} {path} HTTP/1.1\r\n"
            server_writer.write(request_line.encode())
            
            # 发送请求头
            for key, value in headers.items():
                if key.lower() != 'proxy-connection':
                    server_writer.write(f"{key}: {value}\r\n".encode())
            server_writer.write(b'\r\n')
            
            # 发送请求体
            if body:
                server_writer.write(body)
            
            await server_writer.drain()
            
            # 读取响应
            response_data = b''
            while True:
                chunk = await server_reader.read(8192)
                if not chunk:
                    break
                response_data += chunk
                client_writer.write(chunk)
                await client_writer.drain()
            
            # 通知响应
            if self.on_response:
                try:
                    # 解析响应
                    response_text = response_data.decode('utf-8', errors='ignore')
                    lines = response_text.split('\r\n')
                    if lines:
                        status_line = lines[0]
                        status_parts = status_line.split()
                        status_code = int(status_parts[1]) if len(status_parts) > 1 else 0
                        
                        self.on_response({
                            'status_code': status_code,
                            'data': response_text
                        })
                except:
                    pass
            
        except Exception as e:
            print(f"HTTP forward error: {e}")
            error_response = b'HTTP/1.1 502 Bad Gateway\r\n\r\n'
            client_writer.write(error_response)
            await client_writer.drain()
