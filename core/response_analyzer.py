#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
响应分析器 - 分析上传响应结果
"""

import re
import json
from urllib.parse import urljoin


class ResponseAnalyzer:
    """响应分析器类"""
    
    def __init__(self):
        # 成功标识
        self.success_indicators = [
            "上传成功", "success", "uploaded", "file uploaded", "上传完成",
            "文件已上传", "upload complete", "successfully", "成功",
            "upload ok", "upload success", "文件上传成功", "上传OK"
        ]
        
        # 失败标识
        self.failure_indicators = [
            "上传失败", "failed", "error", "invalid", "不允许",
            "文件类型错误", "file type not allowed", "upload failed",
            "forbidden", "blocked", "拒绝", "not allowed", "unsupported",
            "invalid file", "file too large", "extension not allowed"
        ]
        
        # 文件路径模式
        self.path_patterns = [
            r'["\']([^"\']*uploads?/[^"\']+)["\']',
            r'["\']([^"\']*files?/[^"\']+)["\']',
            r'["\']([^"\']*images?/[^"\']+)["\']',
            r'["\']([^"\']*attachments?/[^"\']+)["\']',
            r'["\']([^"\']*media/[^"\']+)["\']',
            r'href=["\']?([^"\'>\s]+\.(?:php|asp|aspx|jsp))["\']?',
            r'src=["\']?([^"\'>\s]+\.(?:php|asp|aspx|jsp))["\']?',
            r'url[\("\']*[:\(]\s*["\']?([^"\'>\s]+)',
            r'path["\']?\s*[:=]\s*["\']?([^"\'>\s]+)',
            r'location["\']?\s*[:=]\s*["\']?([^"\'>\s]+)',
        ]
    
    def analyze(self, response, original_filename=None):
        """分析响应结果"""
        result = {
            "status_code": None,
            "is_success": False,
            "is_failure": False,
            "message": "",
            "uploaded_path": None,
            "full_url": None,
            "response_time": None,
            "content_length": 0,
            "indicators": [],
            "suggestions": []
        }
        
        # 处理错误响应
        if isinstance(response, dict) and "error" in response:
            result["message"] = f"请求错误: {response['error']}"
            result["is_failure"] = True
            return result
        
        try:
            result["status_code"] = response.status_code
            result["response_time"] = response.elapsed.total_seconds()
            result["content_length"] = len(response.content)
            
            content = response.text.lower()
            original_content = response.text
            
            # 检查成功标识
            for indicator in self.success_indicators:
                if indicator.lower() in content:
                    result["is_success"] = True
                    result["indicators"].append(f"发现成功标识: {indicator}")
            
            # 检查失败标识
            for indicator in self.failure_indicators:
                if indicator.lower() in content:
                    result["is_failure"] = True
                    result["indicators"].append(f"发现失败标识: {indicator}")
            
            # 根据状态码判断
            if response.status_code == 200:
                if not result["is_failure"]:
                    result["is_success"] = True
            elif response.status_code in [403, 415, 400]:
                result["is_failure"] = True
                result["suggestions"].append("可能需要使用绕过技术")
            
            # 提取上传路径
            uploaded_path = self._extract_upload_path(original_content, response.url)
            if uploaded_path:
                result["uploaded_path"] = uploaded_path
                result["full_url"] = urljoin(response.url, uploaded_path)
            
            # 生成分析消息
            if result["is_success"] and result["uploaded_path"]:
                result["message"] = f"上传成功！文件路径: {result['uploaded_path']}"
            elif result["is_success"]:
                result["message"] = "上传可能成功，但未找到文件路径"
            elif result["is_failure"]:
                result["message"] = "上传被阻止"
            else:
                result["message"] = "无法确定上传结果"
            
        except Exception as e:
            result["message"] = f"分析错误: {str(e)}"
        
        return result
    
    def _extract_upload_path(self, content, base_url):
        """提取上传文件路径"""
        for pattern in self.path_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                # 返回第一个匹配的路径
                path = matches[0]
                # 清理路径
                path = path.strip('"\'<>')
                return path
        
        # 尝试从JSON响应中提取
        try:
            data = json.loads(content)
            # 常见的路径字段名
            path_keys = ['path', 'url', 'file', 'filename', 'location', 
                        'link', 'src', 'href', 'file_path', 'file_url']
            for key in path_keys:
                if key in data:
                    return str(data[key])
        except:
            pass
        
        return None
    
    def check_webshell_execution(self, response, expected_content=None):
        """检查webshell是否可执行"""
        result = {
            "is_executable": False,
            "evidence": [],
            "output": None
        }
        
        if isinstance(response, dict) and "error" in response:
            return result
        
        content = response.text
        
        # 检查PHP信息特征
        php_indicators = [
            "phpinfo", "PHP Version", "System", "Build Date",
            "Server API", "Loaded Extensions"
        ]
        
        for indicator in php_indicators:
            if indicator in content:
                result["is_executable"] = True
                result["evidence"].append(f"发现PHP特征: {indicator}")
        
        # 检查命令执行输出特征
        command_indicators = [
            r"root:.*:0:0:",  # /etc/passwd
            r"uid=\d+.*gid=\d+",  # id命令输出
            r"Windows NT",  # Windows系统
            r"Microsoft Windows",  # Windows
            r"Directory of",  # Windows dir命令
        ]
        
        for pattern in command_indicators:
            if re.search(pattern, content):
                result["is_executable"] = True
                result["evidence"].append(f"发现命令执行特征: {pattern}")
        
        # 检查预期内容
        if expected_content and expected_content in content:
            result["is_executable"] = True
            result["evidence"].append("发现预期响应内容")
        
        result["output"] = content[:1000]  # 限制输出长度
        
        return result
    
    def compare_responses(self, baseline_response, test_response):
        """比较两个响应的差异"""
        differences = {
            "status_code_changed": False,
            "content_changed": False,
            "size_changed": False,
            "differences": []
        }
        
        if isinstance(baseline_response, dict) or isinstance(test_response, dict):
            return differences
        
        # 比较状态码
        if baseline_response.status_code != test_response.status_code:
            differences["status_code_changed"] = True
            differences["differences"].append(
                f"状态码变化: {baseline_response.status_code} -> {test_response.status_code}"
            )
        
        # 比较内容长度
        baseline_len = len(baseline_response.content)
        test_len = len(test_response.content)
        
        if abs(baseline_len - test_len) > 100:  # 允许100字节的差异
            differences["size_changed"] = True
            differences["differences"].append(
                f"内容长度变化: {baseline_len} -> {test_len}"
            )
        
        # 简单比较内容
        if baseline_response.text != test_response.text:
            differences["content_changed"] = True
            differences["differences"].append("响应内容发生变化")
        
        return differences
    
    def detect_waf(self, response):
        """检测是否存在WAF"""
        waf_signatures = {
            "Cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
            "AWS WAF": ["awselb", "aws-waf"],
            "ModSecurity": ["mod_security", "modsecurity"],
            "Sucuri": ["sucuri", "x-sucuri"],
            "Incapsula": ["incap_ses", "visid_incap"],
            "Akamai": ["akamai", "akamai-ghost"],
            "F5 BIG-IP": ["bigip", "f5", "x-waf-status"],
            "Imperva": ["imperva", "incap_ses"],
            "Barracuda": ["barra"],
            "Fortinet": ["fortigate", "fortiwaf"],
        }
        
        detected_wafs = []
        
        if isinstance(response, dict):
            return detected_wafs
        
        headers_str = str(response.headers).lower()
        content = response.text.lower()
        
        for waf_name, signatures in waf_signatures.items():
            for sig in signatures:
                if sig.lower() in headers_str or sig.lower() in content:
                    detected_wafs.append(waf_name)
                    break
        
        # 检查特定的WAF阻止页面
        if response.status_code == 403:
            if "access denied" in content or "forbidden" in content:
                detected_wafs.append("Generic WAF (403 Forbidden)")
        
        return detected_wafs
    
    def get_security_headers(self, response):
        """获取安全相关响应头"""
        security_headers = {}
        
        if isinstance(response, dict):
            return security_headers
        
        important_headers = [
            "X-Frame-Options",
            "X-XSS-Protection",
            "X-Content-Type-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Permitted-Cross-Domain-Policies",
            "Referrer-Policy",
            "Feature-Policy",
            "Server",
            "X-Powered-By"
        ]
        
        for header in important_headers:
            value = response.headers.get(header)
            if value:
                security_headers[header] = value
        
        return security_headers
