import re

# 忽略的目录（不扫描）
IGNORE_DIRS = {
    '.git', 'node_modules', 'venv', 'env', '.env', 'dist', 'build',
    '__pycache__', '.pytest_cache', '.vscode', '.idea'
}

# 忽略的文件扩展名
IGNORE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico',
                     '.mp4', '.mp3', '.wav', '.pdf', '.doc', '.docx',
                     '.xls', '.xlsx', '.zip', '.tar', '.gz', '.rar'}

# API密钥检测模式
SENSITIVE_PATTERNS = [
    re.compile(r'sk-[a-zA-Z0-9]{32,}'),
    re.compile(r'sk-proj-[a-zA-Z0-9_-]{32,}'),
    re.compile(r'sk-ant-[a-zA-Z0-9_-]{32,}'),
    re.compile(r'AIza[a-zA-Z0-9_-]{35}'),
    re.compile(r'[a-zA-Z0-9]{40}'),
    re.compile(r'hf_[a-zA-Z0-9]{20,}'),
    re.compile(r'r8_[a-zA-Z0-9]{32,}'),
    re.compile(r'OPENAI_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?'),
    re.compile(r'ANTHROPIC_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?'),
    re.compile(r'GOOGLE_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?'),
    re.compile(r'COHERE_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?'),
    re.compile(r'HUGGINGFACE_API_KEY[\s]*=[\s]*["\']?([a-zA-Z0-9_-]{20,})["\']?'),
    re.compile(r'apiKey[\s]*:[\s]*["\']([a-zA-Z0-9_-]{20,})["\']'),
    re.compile(r'openaiApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']'),
    re.compile(r'anthropicApiKey[\s]*[:=][\s]*["\']([a-zA-Z0-9_-]{20,})["\']'),
    re.compile(r'[a-zA-Z0-9]{32,}'),
]

EXAMPLE_KEYWORDS = {
    'example', 'sample', 'demo', 'test', 'placeholder',
    'your_api_key', 'xxx', 'todo', 'replace', 'change_me',
    'your_key_here', 'api_key_here'
}
