import re
from typing import List, Dict
from config import SENSITIVE_PATTERNS, EXAMPLE_KEYWORDS, IGNORE_DIRS, IGNORE_EXTENSIONS
import os

class SecretDetector:
    def __init__(self):
        self.patterns = SENSITIVE_PATTERNS
        self.example_keywords = EXAMPLE_KEYWORDS

    def detect_secrets_in_text(self, text: str, file_path: str = "") -> List[Dict]:
        findings = []
        lines = text.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue

            for pattern in self.patterns:
                matches = pattern.finditer(line)
                for match in matches:
                    secret = match.group(0)
                    if self._is_likely_example(line, secret):
                        continue
                    if self._is_likely_fake_secret(secret):   # 新增过滤
                        continue
                    if len(secret) < 8:
                        continue
                    if self._is_likely_hash_or_uuid(secret, line):
                        continue
                    
                    findings.append({
                        'file_path': file_path,
                        'line_number': line_num,
                        'line_content': line.strip(),
                        'secret': secret,
                        'pattern': pattern.pattern,
                        'confidence': self._calculate_confidence(secret, line)
                    })
        
        return findings

    def _is_likely_example(self, line: str, secret: str) -> bool:
        line_lower = line.lower()
        for keyword in self.example_keywords:
            if keyword in line_lower:
                return True
        if 'example' in secret.lower() or 'test' in secret.lower():
            return True
        return False

    def _is_likely_fake_secret(self, secret: str) -> bool:
        """判断一个密钥是否明显是假的（示例/占位符）"""
        if len(secret) < 20:
            return True  # 太短不可能是真实密钥（大部分真实密钥长度>30）

        # 检查是否全是重复字符（如 aaaaaaaa）
        if len(set(secret)) <= 3:
            return True

        # 检查是否按顺序排列（数字顺序、字母顺序、键盘顺序）
        lower = secret.lower()
        sequences = [
            '0123456789',
            'abcdefghijklmnopqrstuvwxyz',
            'qwertyuiopasdfghjklzxcvbnm',
            'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
            'abcdefghijklmnopqrstuvwxyz0123456789',
            '1234567890',
            '1234567890abcdefghijklmnopqrstuvwxyz',
        ]
        for seq in sequences:
            if seq in lower:
                return True

        # 熵值检测：字符种类太少
        unique_chars = set(secret)
        if len(unique_chars) <= 10:
            return True

        # 检查是否全是小写字母或全是数字（真实密钥通常大小写混合）
        if secret.islower() or secret.isdigit():
            return True
        # 如果全是字母（无数字或下划线），也可能是假的，但有些密钥可能只有字母（如旧版OpenAI），所以放宽
        if secret.isalpha() and (secret.islower() or secret.isupper()):
            # 如果全是大小写混合，但长度刚好是32位，且只有字母，也可能真实，我们不做过度过滤
            # 我们可以检查是否包含连续重复的字母模式
            # 进一步检测：是否包含常见单词，比如'password', 'secret'等
            common_words = ['password', 'secret', 'key', 'token', 'example']
            if any(word in secret.lower() for word in common_words):
                return True

        return False

    def _is_likely_hash_or_uuid(self, secret: str, line: str) -> bool:
        if re.fullmatch(r'[a-fA-F0-9]{32,64}', secret):
            return True
        if re.fullmatch(r'[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}', secret):
            return True
        return False

    def _calculate_confidence(self, secret: str, line: str) -> str:
        if secret.startswith(('sk-', 'sk-proj-', 'sk-ant-', 'AIza', 'hf_', 'r8_')):
            return 'high'
        if any(key in line for key in ['API_KEY', 'apiKey', 'ApiKey']):
            return 'medium'
        return 'low'

    def should_scan_file(self, file_path: str) -> bool:
        dirs = file_path.split(os.sep)
        for d in dirs:
            if d in IGNORE_DIRS:
                return False
        ext = os.path.splitext(file_path)[1].lower()
        if ext in IGNORE_EXTENSIONS:
            return False
        if os.path.exists(file_path) and os.path.getsize(file_path) > 1024 * 1024:
            return False
        return True
