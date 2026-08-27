import os
from datetime import datetime
from typing import List, Dict

class ReportGenerator:
    def __init__(self, output_dir: str = "scan_reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_report(self, scan_results: List[Dict], 
                       scan_start_time: datetime,
                       scan_type: str = "auto") -> str:
        """生成扫描报告（流式写入）"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_report_{timestamp}.txt"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            # 报告头
            f.write("╔" + "═" * 78 + "╗\n")
            f.write("║" + "          🔒 InCloud GitHub 云上扫描器 - 扫描报告".ljust(78) + "║\n")
            f.write("╚" + "═" * 78 + "╝\n\n")
            
            # 扫描信息
            f.write("📋 扫描信息\n")
            f.write("━" * 78 + "\n")
            f.write(f"  🕐 扫描时间:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  🎯 扫描类型:     {scan_type}\n")
            f.write(f"  🔴 发现问题数:   {len(scan_results)} 个\n")
            repos = set(r.get('repo_url', 'unknown') for r in scan_results)
            f.write(f"  📦 涉及仓库数:   {len(repos)} 个\n\n")
            
            if not scan_results:
                f.write("✅ 未发现任何API密钥泄露。\n")
                return filepath

            # 按仓库分组
            results_by_repo = self._group_by_repo(scan_results)
            for repo_url, findings in results_by_repo.items():
                f.write("╭" + "─" * 78 + "╮\n")
                f.write(f"│ 📦 仓库: {repo_url}\n")
                f.write("╰" + "─" * 78 + "╯\n\n")
                for idx, finding in enumerate(findings, 1):
                    self._write_single_finding(f, finding, idx)
            
            # 统计信息
            self._write_statistics(f, scan_results)
            self._write_recommendations(f)
        
        return filepath

    def _group_by_repo(self, scan_results: List[Dict]) -> Dict:
        groups = {}
        for item in scan_results:
            url = item.get('repo_url', 'unknown')
            groups.setdefault(url, []).append(item)
        return groups

    def _write_single_finding(self, f, finding: Dict, idx: int):
        confidence = finding.get('confidence', 'low')
        emoji = {'high': '🔴', 'medium': '🟡', 'low': '🟢'}.get(confidence, '⚪')
        level = {'high': '高危 - 立即处理', 'medium': '中危 - 建议处理', 'low': '低危 - 可忽略'}.get(confidence, '未知')
        f.write(f"  ┌─ 问题 #{idx} ──────────────────────────────────────────────────────────────────\n")
        f.write(f"  │\n")
        f.write(f"  │ {emoji} 风险等级: {level}\n")
        f.write(f"  │\n")
        f.write(f"  │ 📄 文件路径: {finding.get('file_path', 'unknown')}\n")
        f.write(f"  │ 📍 行号: {finding.get('line_number', '?')}\n")
        f.write(f"  │\n")
        secret = finding.get('secret', '')
        masked = self._mask_secret(secret)
        f.write(f"  │ 🔑 密钥内容: {masked}\n")
        f.write(f"  │ 🎯 匹配规则: {finding.get('pattern', '')}\n")
        f.write(f"  │\n")
        f.write(f"  │ 💻 代码片段:\n")
        # 截断过长的代码行，避免报告过大
        line_content = finding.get('line_content', '')[:200]
        f.write(f"  │    {line_content}\n")
        f.write(f"  │\n")
        f.write(f"  └──────────────────────────────────────────────────────────────────────────────\n\n")

    def _mask_secret(self, secret: str) -> str:
        if len(secret) <= 8:
            return "*" * len(secret)
        return f"{secret[:4]}{'*' * (len(secret) - 8)}{secret[-4:]}"

    def _write_statistics(self, f, scan_results: List[Dict]):
        f.write("\n📊 统计信息\n")
        f.write("━" * 78 + "\n")
        high = sum(1 for r in scan_results if r.get('confidence') == 'high')
        medium = sum(1 for r in scan_results if r.get('confidence') == 'medium')
        low = sum(1 for r in scan_results if r.get('confidence') == 'low')
        f.write(f"  🔴 高危: {high}\n")
        f.write(f"  🟡 中危: {medium}\n")
        f.write(f"  🟢 低危: {low}\n")

    def _write_recommendations(self, f):
        f.write("\n🛡️ 安全建议\n")
        f.write("━" * 78 + "\n")
        f.write("  1. 立即撤销泄露的API密钥（在服务商控制台操作）\n")
        f.write("  2. 检查密钥是否被滥用（查看访问日志）\n")
        f.write("  3. 从Git历史中彻底删除敏感信息（使用 git filter-branch 或 BFG）\n")
        f.write("  4. 使用环境变量或密钥管理服务（如Vault）存储密钥\n")
        f.write("  5. 在.gitignore中添加.env等敏感文件\n")
