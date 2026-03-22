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
    
    # 成功关键词（避免过短的 ok/done/成功 等，防止页面脚本或无关词误判）
    SUCCESS_KEYWORDS = [
        "uploaded", "upload success", "successfully", "completed", "saved",
        "上传成功", "上传完成", "文件已上传", "文件已保存",
        "upload complete", "file saved", "完成",
        "upload successful", "upload ok",
    ]
    
    # 失败关键词 - 扩展列表
    FAILURE_KEYWORDS = [
        "error", "failed", "invalid", "blocked", "forbidden", "not allowed",
        "上传失败", "错误", "不允许", "无效", "拒绝",
        # 中文错误提示增强
        "文件未知", "上传失败！", "上传错误", "类型不允许",
        "后缀不允许", "格式不正确", "文件过大", "上传被阻止",
        "非法文件", "恶意文件", "危险文件", "禁止上传",
        "文件类型错误", "extension not allowed", "unsupported"
    ]
    
    def analyze_upload_response(self, response: httpx.Response, filename: str) -> Dict:
        """分析上传响应 - 302重定向也算作成功"""
        result = {
            "success_probability": 0,
            "path_leaked": None,
            "status_code": response.status_code,
            "length": len(response.content),
            "is_success": False,
            "is_redirect": False,
            "error_messages": [],
            "success_messages": []
        }
        
        text = response.text
        text_lower = text.lower()
        
        # 明确的上传失败/成功短语（靶场页面常见），失败优先于泛化关键词
        explicit_fail = [
            "上传失败", "文件未知", "上传错误", "类型不允许", "后缀不允许",
            "upload failed", "file type not allowed", "upload error",
        ]
        has_explicit_fail = any(m.lower() in text_lower for m in explicit_fail)
        if has_explicit_fail:
            result["success_probability"] = 5
            result["is_success"] = False
            result["path_leaked"] = None
            return result
        
        # 【关键修复】先检查失败关键词，优先级最高
        has_failure = False
        for keyword in self.FAILURE_KEYWORDS:
            if keyword.lower() in text_lower:
                has_failure = True
                result["error_messages"].append(keyword)
                break
        
        # 检查成功关键词
        has_success = False
        for keyword in self.SUCCESS_KEYWORDS:
            if keyword.lower() in text_lower:
                has_success = True
                result["success_messages"].append(keyword)
                break
        
        # 【关键修复】如果有失败关键词且没有成功关键词，判定为失败
        if has_failure and not has_success:
            result["success_probability"] = 5
            result["is_success"] = False
            result["path_leaked"] = None
            return result
        
        # 1. 状态码检查 - 200-399都算成功 (包括302重定向)
        if 200 <= response.status_code < 400:
            # 【修复】如果有失败关键词，即使状态码200也判定失败
            if has_failure:
                result["success_probability"] = 10
                result["is_success"] = False
            else:
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
        if filename in response.text and not has_failure:
            result["success_probability"] += 30
        
        # 3. 成功关键词（不得覆盖已判失败）
        if has_success and not has_failure:
            result["success_probability"] += 30
            result["is_success"] = True
        
        # 5. 尝试提取路径
        result["path_leaked"] = self._extract_path(text, filename)
        
        # 如果有上传路径，提高成功率（失败语境下不强行判成功）
        if result["path_leaked"] and not has_failure:
            result["success_probability"] += 20
            result["is_success"] = True
        
        # 6. Location头检查 (重定向目标) — 失败响应也可能带跳转，不覆盖 path 为成功依据
        location = response.headers.get('location', '')
        if location and not has_failure:
            result["path_leaked"] = location
        
        # 【修复】确保概率不超过100
        result["success_probability"] = min(100, max(0, result["success_probability"]))
        if has_failure:
            result["is_success"] = False
            result["success_probability"] = min(result["success_probability"], 15)
        
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
