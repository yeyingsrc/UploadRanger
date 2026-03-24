#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
异步响应分析器
"""

import json
import re
import httpx
from typing import Dict, Optional, List

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
        "failed", "invalid", "blocked", "forbidden", "not allowed",
        "上传失败", "错误", "不允许", "无效", "拒绝",
        # 中文错误提示增强
        "文件未知", "上传失败！", "上传错误", "类型不允许",
        "后缀不允许", "格式不正确", "文件过大", "上传被阻止",
        "非法文件", "恶意文件", "危险文件", "禁止上传",
        "文件类型错误", "extension not allowed", "unsupported"
    ]
    
    def analyze_upload_response(self, response: httpx.Response, filename: str) -> Dict:
        """分析上传响应 - 证据分层 + 冲突裁决"""
        result = {
            "success_probability": 0,
            "path_leaked": None,
            "status_code": response.status_code,
            "length": len(response.content),
            "is_success": False,
            "is_redirect": False,
            "error_messages": [],
            "success_messages": [],
            "decision_reasons": [],
            "confidence_level": "low",
            "server_filename": None,
            "verify_filenames": []
        }
        
        text = response.text
        text_lower = text.lower()
        reasons: List[str] = []
        score = 0
        
        # 0. 先做结构化 JSON 判定（优先级最高）
        data = self._try_parse_json(response)
        has_strong_success = False
        has_strong_failure = False
        if isinstance(data, dict):
            success_val = data.get("success")
            if success_val is True:
                score += 60
                has_strong_success = True
                reasons.append("JSON success=true")
            
            files_val = data.get("files")
            if isinstance(files_val, list) and len(files_val) > 0:
                score += 25
                has_strong_success = True
                reasons.append(f"JSON files 列表非空({len(files_val)})")
            
            # errors=null 不应被当成失败；只有 errors 有实际内容才算失败证据
            errors_val = data.get("errors")
            if isinstance(errors_val, str) and errors_val.strip():
                score -= 70
                has_strong_failure = True
                result["error_messages"].append(errors_val.strip())
                reasons.append("JSON errors 为非空字符串")
            elif isinstance(errors_val, list) and any(str(x).strip() for x in errors_val):
                score -= 70
                has_strong_failure = True
                result["error_messages"].extend([str(x).strip() for x in errors_val if str(x).strip()])
                reasons.append("JSON errors 列表包含错误内容")
            
            # message 文案作为弱证据
            msg = data.get("message")
            if isinstance(msg, str) and msg.strip():
                msg_lower = msg.lower()
                if any(k in msg_lower for k in ["成功", "saved", "uploaded", "complete"]):
                    score += 15
                    reasons.append("JSON message 包含成功语义")
                if any(k in msg_lower for k in ["失败", "错误", "blocked", "forbidden"]):
                    score -= 20
                    reasons.append("JSON message 包含失败语义")
            
            # 服务端重命名后的文件名提取
            server_filename = self._extract_server_filename(data)
            if server_filename:
                result["server_filename"] = server_filename
                reasons.append(f"发现服务端保存名: {server_filename}")
        
        # 1. 明确的上传失败短语（靶场页面常见），失败优先于泛化关键词
        explicit_fail = [
            "上传失败", "文件未知", "上传错误", "类型不允许", "后缀不允许",
            "upload failed", "file type not allowed", "upload error",
        ]
        has_explicit_fail = any(m.lower() in text_lower for m in explicit_fail)
        if has_explicit_fail and not has_strong_success:
            score -= 70
            has_strong_failure = True
            reasons.append("命中明确失败短语")
        
        # 2. 失败/成功关键词（弱证据）
        has_failure = False
        for keyword in self.FAILURE_KEYWORDS:
            if keyword.lower() in text_lower:
                has_failure = True
                result["error_messages"].append(keyword)
                score -= 25
                reasons.append(f"命中失败关键词: {keyword}")
                break
        
        has_success = False
        for keyword in self.SUCCESS_KEYWORDS:
            if keyword.lower() in text_lower:
                has_success = True
                result["success_messages"].append(keyword)
                score += 20
                reasons.append(f"命中成功关键词: {keyword}")
                break
        
        # 3. 状态码证据（弱到中）
        if 200 <= response.status_code < 400:
            score += 25
            reasons.append(f"状态码 {response.status_code} 属于 2xx/3xx")
            
            # 302/301重定向通常表示上传成功并跳转到结果页
            if 300 <= response.status_code < 400:
                result["is_redirect"] = True
                score += 10
                reasons.append("重定向响应")
        elif response.status_code in [403, 401]:
            score -= 50
            reasons.append(f"状态码 {response.status_code} 拒绝访问")
        elif response.status_code == 500:
            score += 5
            reasons.append("状态码 500（可能触发后端处理异常）")
        
        # 4. 文件名回显（弱成功证据）
        if filename in response.text:
            score += 15
            reasons.append("响应中包含上传文件名")
        
        # 5. 路径提取（中证据）
        result["path_leaked"] = self._extract_path(text, filename)
        if result["path_leaked"]:
            score += 20
            reasons.append(f"提取到路径: {result['path_leaked']}")
        
        # 6. Location 头作为路径候选
        location = response.headers.get('location', '')
        if location:
            result["path_leaked"] = location
            score += 10
            reasons.append(f"Location: {location}")
        
        # 7. 冲突裁决（强证据优先）
        if has_strong_success and not has_strong_failure:
            result["is_success"] = True
            reasons.append("强成功证据胜出")
        elif has_strong_failure and not has_strong_success:
            result["is_success"] = False
            reasons.append("强失败证据胜出")
        else:
            # 无强证据或冲突时按分数裁决
            result["is_success"] = score >= 50
            reasons.append("按综合分裁决")
        
        # 8. 置信度与输出字段
        result["success_probability"] = min(100, max(0, score))
        if result["success_probability"] >= 85:
            result["confidence_level"] = "high"
        elif result["success_probability"] >= 55:
            result["confidence_level"] = "medium"
        else:
            result["confidence_level"] = "low"
        
        # 验证候选文件名（用于后续 upload_dir 验证）
        verify_candidates: List[str] = []
        verify_candidates.append(filename.split("%00")[0] if "%00" in filename else filename)
        if result.get("server_filename"):
            verify_candidates.append(result["server_filename"])
        if result.get("path_leaked"):
            leaked = result["path_leaked"].split("?")[0].split("#")[0].rstrip("/")
            if "/" in leaked:
                verify_candidates.append(leaked.rsplit("/", 1)[-1])
            else:
                verify_candidates.append(leaked)
        # 去重并过滤空值
        seen = set()
        result["verify_filenames"] = []
        for name in verify_candidates:
            name = (name or "").strip()
            if name and name not in seen:
                seen.add(name)
                result["verify_filenames"].append(name)
        
        result["decision_reasons"] = reasons[:8]
        
        return result

    def _try_parse_json(self, response: httpx.Response):
        """尝试解析 JSON 响应体，失败返回 None。"""
        ctype = (response.headers.get("content-type", "") or "").lower()
        text = response.text.strip()
        if "application/json" not in ctype and not (text.startswith("{") or text.startswith("[")):
            return None
        try:
            return response.json()
        except Exception:
            try:
                return json.loads(text)
            except Exception:
                return None

    def _extract_server_filename(self, data: dict) -> Optional[str]:
        """从结构化 JSON 中提取服务端保存后的文件名。"""
        # 常见: {"files":[{"saved":"2026_xxx.php","filename":"a.php"}]}
        files = data.get("files")
        if isinstance(files, list):
            for item in files:
                if isinstance(item, dict):
                    for key in ("saved", "savedName", "save_name", "stored_name", "filename", "name"):
                        val = item.get(key)
                        if isinstance(val, str) and val.strip():
                            return val.strip()
        # 其他扁平字段
        for key in ("saved", "savedName", "save_name", "stored_name", "filename", "name"):
            val = data.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
        # 文本兜底（避免复杂后端漏掉）
        text = json.dumps(data, ensure_ascii=False)
        m = re.search(r'(\d{8}_\d{6}_[^"\s]+)', text)
        if m:
            return m.group(1)
        return None
    
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
