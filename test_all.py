#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UploadRanger 功能测试脚本
"""

import sys
import os

def test_imports():
    """测试模块导入"""
    print("=" * 50)
    print("测试模块导入")
    print("=" * 50)
    
    tests = [
        ("config", "配置模块"),
        ("core.http_client", "HTTPClient (同步)"),
        ("core.form_parser", "FormParser"),
        ("core.response_analyzer", "ResponseAnalyzer (同步)"),
        ("core.scanner", "UploadScanner (同步)"),
        ("core.models", "数据模型 (TrafficLog, VulnerabilityFinding)"),
        ("core.async_http_client", "AsyncHTTPClient (异步)"),
        ("core.async_response_analyzer", "AsyncResponseAnalyzer (异步)"),
        ("core.async_scanner", "AsyncScanner (异步)"),
        ("payloads.webshells", "WebShellGenerator"),
        ("payloads.bypass_payloads", "BypassPayloadGenerator"),
        ("payloads.polyglots", "PolyglotGenerator"),
        ("gui.themes.dark_theme", "DarkTheme"),
        ("gui.traffic_viewer", "TrafficViewer"),
    ]
    
    passed = 0
    failed = 0
    
    for module, name in tests:
        try:
            __import__(module)
            print(f"✓ {name}")
            passed += 1
        except Exception as e:
            print(f"✗ {name}: {e}")
            failed += 1
    
    print(f"\n结果: {passed} 通过, {failed} 失败")
    return failed == 0

def test_models():
    """测试数据模型"""
    print("\n" + "=" * 50)
    print("测试 数据模型")
    print("=" * 50)
    
    from core.models import TrafficLog, VulnerabilityFinding, ScanResult
    from datetime import datetime
    
    # 测试TrafficLog
    log = TrafficLog(
        id=1,
        timestamp="12:00:00",
        method="POST",
        url="http://example.com/upload",
        status_code=200,
        request_headers="Content-Type: multipart/form-data",
        request_body="--boundary",
        response_headers="HTTP/1.1 200 OK",
        response_body="Upload success"
    )
    print(f"✓ TrafficLog 创建成功: ID={log.id}")
    
    # 测试VulnerabilityFinding
    finding = VulnerabilityFinding(
        name="任意文件上传",
        description="成功上传PHP文件",
        risk_level="高危",
        confidence="确定",
        url="http://example.com/upload",
        payload="shell.php",
        proof="文件可访问",
        remediation="验证文件扩展名"
    )
    print(f"✓ VulnerabilityFinding 创建成功: {finding.name}")
    
    # 测试ScanResult
    result = ScanResult(
        target="http://example.com",
        start_time=datetime.now()
    )
    print(f"✓ ScanResult 创建成功: {result.target}")
    
    return True

def test_async_components():
    """测试异步组件"""
    print("\n" + "=" * 50)
    print("测试 异步组件")
    print("=" * 50)
    
    from core.async_http_client import AsyncHTTPClient
    from core.async_response_analyzer import AsyncResponseAnalyzer
    from core.async_scanner import AsyncScanner
    
    # 测试AsyncHTTPClient
    client = AsyncHTTPClient()
    print("✓ AsyncHTTPClient 创建成功")
    
    # 测试AsyncResponseAnalyzer
    analyzer = AsyncResponseAnalyzer()
    print("✓ AsyncResponseAnalyzer 创建成功")
    
    # 测试AsyncScanner
    scanner = AsyncScanner()
    print("✓ AsyncScanner 创建成功")
    print(f"  - 生成 {len(scanner._generate_payloads())} 个payloads")
    
    return True

def test_webshell_generator():
    """测试WebShell生成器"""
    print("\n" + "=" * 50)
    print("测试 WebShell 生成器")
    print("=" * 50)
    
    from payloads.webshells import WebShellGenerator
    
    gen = WebShellGenerator()
    
    php_shells = gen.get_php_shells()
    print(f"✓ PHP Shells: {len(php_shells)} 个")
    
    asp_shells = gen.get_asp_shells()
    print(f"✓ ASP Shells: {len(asp_shells)} 个")
    
    jsp_shells = gen.get_jsp_shells()
    print(f"✓ JSP Shells: {len(jsp_shells)} 个")
    
    shell = gen.generate_shell("php", "simple_eval")
    if shell:
        print(f"✓ 成功生成 simple_eval Shell")
    
    return True

def test_bypass_payloads():
    """测试绕过Payload生成器"""
    print("\n" + "=" * 50)
    print("测试 绕过Payload生成器")
    print("=" * 50)
    
    from payloads.bypass_payloads import BypassPayloadGenerator
    
    gen = BypassPayloadGenerator()
    payloads = gen.generate_all_payloads("test", ".php")
    print(f"✓ 绕过Payloads: {len(payloads)} 个")
    
    techniques = set(p.get("technique") for p in payloads)
    print(f"✓ 包含 {len(techniques)} 种绕过技术")
    
    return True

def test_polyglots():
    """测试Polyglot生成器"""
    print("\n" + "=" * 50)
    print("测试 Polyglot 生成器")
    print("=" * 50)
    
    from payloads.polyglots import PolyglotGenerator
    
    gen = PolyglotGenerator()
    polyglots = gen.get_all_polyglots()
    print(f"✓ Polyglot类型: {len(polyglots)} 种")
    
    gif_php = gen.create_gif_php("<?php echo 'test'; ?>")
    print(f"✓ GIF+PHP polyglot: {len(gif_php)} bytes")
    
    return True

def test_config():
    """测试配置"""
    print("\n" + "=" * 50)
    print("测试 配置")
    print("=" * 50)
    
    import config
    
    print(f"✓ 应用名称: {config.APP_NAME}")
    print(f"✓ 版本: {config.VERSION}")
    print(f"✓ 作者: {config.AUTHOR}")
    print(f"✓ 支持 {len(config.SCAN_CONFIG['allowed_extensions'])} 种语言扩展名")
    print(f"✓ 支持多种绕过技术")
    
    return True

def main():
    """主函数"""
    print("\n" + "=" * 50)
    print("UploadRanger 功能测试")
    print("=" * 50 + "\n")
    
    results = []
    
    results.append(("模块导入", test_imports()))
    results.append(("数据模型", test_models()))
    results.append(("异步组件", test_async_components()))
    results.append(("配置", test_config()))
    results.append(("WebShell生成器", test_webshell_generator()))
    results.append(("绕过Payload生成器", test_bypass_payloads()))
    results.append(("Polyglot生成器", test_polyglots()))
    
    print("\n" + "=" * 50)
    print("测试总结")
    print("=" * 50)
    
    for name, result in results:
        status = "✓ 通过" if result else "✗ 失败"
        print(f"{status} - {name}")
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    print(f"\n总计: {passed}/{total} 测试通过")
    
    if passed == total:
        print("\n✓ 所有测试通过!")
        return 0
    else:
        print(f"\n✗ {total - passed} 个测试失败")
        return 1

if __name__ == "__main__":
    sys.exit(main())
