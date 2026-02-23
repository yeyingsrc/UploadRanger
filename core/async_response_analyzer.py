#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
异步响应分析器
"""

import httpx
from typing import Dict, Optional

from .models import (
    VulnerabilityFinding, 
    RISK_CRITICAL, RISK_HIGH, RISK_MEDIUM, RISK_LOW,
    CONFIDENCE_CERTAIN, CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW
)


class AsyncResponseAnalyzer:
    """异步响应分析器"""
    
    # 成功关键词
    SUCCESS_KEYWORDS = [
        "uploaded", "success", "completed", "saved", "上传成功", "成功",
        "upload complete", "file saved", "done", "ok", "完成"
    ]
    
    # 失败关键词
    FAILURE_KEYWORDS = [
        "error", "failed", "invalid", "blocked", "forbidden", "not allowed",
        "上传失败", "错误", "不允许", "无效", "拒绝"
    ]
    
    def analyze_upload_response(self, response: httpx.Response, filename: str) -> Dict:
        """分析上传响应 - 302重定向也算作成功"""
        result = {
            "success_probability": 0,
            "path_leaked": None,
            "status_code": response.status_code,
            "length": len(response.content),
            "is_success": False,
            "is_redirect": False
        }
        
        # 1. 状态码检查 - 200-399都算成功 (包括302重定向)
        if 200 <= response.status_code < 400:
            result["success_probability"] += 50
            result["is_success"] = True
            
            # 302/301重定向通常表示上传成功并跳转到结果页
            if 300 <= response.status_code < 400:
                result["is_redirect"] = True
                result["success_probability"] += 20
        elif response.status_code in [403, 401]:
            result["success_probability"] -= 50
            result["is_success"] = False
        elif response.status_code == 500:
            # 500可能意味着服务器尝试处理时崩溃，这可能是有趣的
            result["success_probability"] += 10
        
        # 2. 文件名反射
        if filename in response.text:
            result["success_probability"] += 30
        
        # 3. 成功关键词
        text_lower = response.text.lower()
        for keyword in self.SUCCESS_KEYWORDS:
            if keyword in text_lower:
                result["success_probability"] += 30
                result["is_success"] = True
                break
        
        # 4. 失败关键词检查
        for keyword in self.FAILURE_KEYWORDS:
            if keyword in text_lower:
                result["success_probability"] -= 40
                result["is_success"] = False
                break
        
        # 5. 尝试提取路径
        result["path_leaked"] = self._extract_path(response.text, filename)
        
        # 6. Location头检查 (重定向目标)
        location = response.headers.get('location', '')
        if location:
            result["path_leaked"] = location
        
        return result
    
    def _extract_path(self, text: str, filename: str) -> Optional[str]:
        """从响应中提取文件路径"""
        import re
        
        # 常见的路径模式
        patterns = [
            r'["\']([^"\']*uploads?/[^"\']*' + re.escape(filename) + r')["\']',
            r'["\']([^"\']*files?/[^"\']*' + re.escape(filename) + r')["\']',
            r'["\']([^"\']*images?/[^"\']*' + re.escape(filename) + r')["\']',
            r'href=["\']?([^"\'>\s]*' + re.escape(filename) + r')["\']?',
            r'src=["\']?([^"\'>\s]*' + re.escape(filename) + r')["\']?',
            r'path["\']?\s*[:=]\s*["\']?([^"\'>\s]*' + re.escape(filename) + r')["\']?',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def analyze_execution_response(self, response: httpx.Response, expected_output: str) -> bool:
        """检查payload是否执行"""
        if response.status_code == 200:
            if expected_output in response.text:
                return True
        return False
    
    def create_finding(self,
                       name: str,
                       description: str,
                       risk_level: str,
                       confidence: str,
                       url: str,
                       payload: str,
                       proof: str,
                       remediation: str,
                       request_data: Optional[str] = None,
                       response_data: Optional[str] = None) -> VulnerabilityFinding:
        """创建漏洞发现"""
        return VulnerabilityFinding(
            name=name,
            description=description,
            risk_level=risk_level,
            confidence=confidence,
            url=url,
            payload=payload,
            proof=proof,
            remediation=remediation,
            request_data=request_data,
            response_data=response_data
        )
