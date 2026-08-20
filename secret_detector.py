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
