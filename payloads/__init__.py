# Payloads Module
"""
文件上传绕过Payload生成模块

包含:
- bypass_payloads: 基础绕过技术 (37+种)
- intruder_payloads: 高级Intruder Payload引擎 (策略模式)
- webshells: WebShell生成器
- polyglots: 多语言Payload生成器
"""

from .bypass_payloads import BypassPayloadGenerator, generate_bypass_payloads
from .intruder_payloads import (
    PayloadFactory,
    FuzzConfig,
    FuzzStrategy,
    generate_intruder_payloads,
    get_payload_statistics,
    BACKEND_LANGUAGES,
    MAGIC_BYTES,
    WEBSHELL_TEMPLATES,
)
from .webshells import WebShellGenerator
from .polyglots import PolyglotGenerator

__all__ = [
    # Bypass Payloads
    'BypassPayloadGenerator',
    'generate_bypass_payloads',
    
    # Intruder Payloads
    'PayloadFactory',
    'FuzzConfig',
    'FuzzStrategy',
    'generate_intruder_payloads',
    'get_payload_statistics',
    
    # Constants
    'BACKEND_LANGUAGES',
    'MAGIC_BYTES',
    'WEBSHELL_TEMPLATES',
    
    # Webshells & Polyglots
    'WebShellGenerator',
    'PolyglotGenerator',
]

