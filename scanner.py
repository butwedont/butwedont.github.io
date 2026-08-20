import os
import time
from datetime import datetime
from typing import List, Dict, Optional
from github_scanner import GitHubScanner
from secret_detector import SecretDetector
from report_generator import ReportGenerator
from scan_history import ScanHistory

class CloudScanner:
    def __init__(self, token: str = None):
        self.github_scanner = GitHubScanner(token)
        self.detector = SecretDetector()
        self.report_generator = ReportGenerator()
        self.scan_history = ScanHistory()
        self.scan_start_time = time.time()

    def scan_ai_projects(self, max_repos: int = 50) -> str:
        print(f"🚀 开始自动搜索 AI 相关项目")
        self.scan_start_time = time.time()
        
        def is_scanned(repo_full_name: str) -> bool:
            return self.scan_history.is_scanned(repo_full_name)
        
        repos_to_scan = self.github_scanner.search_ai_repos(
            max_repos=max_repos,
            skip_filter=is_scanned
        )
        
        print(f"📦 找到 {len(repos_to_scan)} 个待扫描的仓库")
        all_findings = []
        total = len(repos_to_scan)
        
        for idx, repo in enumerate(repos_to_scan, 1):
            if self._check_timeout(idx, total):
                break
            print(f"🔍 [{idx}/{total}] 扫描仓库: {repo['full_name']}")
            findings = self._scan_repository(repo, scan_type="auto:ai-projects")
            self.scan_history.mark_as_scanned(
                repo['full_name'], 
                len(findings), 
                "auto:ai-projects"
            )
            all_findings.extend(findings)
        
        report_path = self.report_generator.generate_report(
            all_findings, 
            datetime.fromtimestamp(self.scan_start_time),
            scan_type="auto:ai-projects"
        )
        print(f"📄 报告已生成: {report_path}")
        return report_path

    def scan_user_repos(self, username: str, max_repos: int = 50) -> str:
        print(f"👤 扫描用户 {username} 的仓库")
        repos = self.github_scanner.search_ai_repos(max_repos=max_repos)
        return self._scan_repo_list(repos, f"user:{username}")

    def scan_org_repos(self, org: str, max_repos: int = 50) -> str:
        print(f"🏢 扫描组织 {org} 的仓库")
        repos = self.github_scanner.search_ai_repos(max_repos=max_repos)
        return self._scan_repo_list(repos, f"org:{org}")

    def scan_single_repo(self, repo_full_name: str) -> str:
        print(f"📦 扫描单个仓库: {repo_full_name}")
        repo_info = {
            'full_name': repo_full_name,
            'html_url': f"https://github.com/{repo_full_name}",
            'clone_url': f"https://github.com/{repo_full_name}.git",
            'default_branch': 'main'
        }
        findings = self._scan_repository(repo_info, scan_type="single")
        return self.report_generator.generate_report(
            findings,
            datetime.fromtimestamp(self.scan_start_time),
            scan_type=f"single:{repo_full_name}"
        )

    def _scan_repository(self, repo_info: Dict, scan_type: str) -> List[Dict]:
        findings = []
        repo_full_name = repo_info['full_name']
        branch = repo_info.get('default_branch', 'main')
        
        contents = self.github_scanner.get_repo_contents(repo_full_name, branch=branch)
        if not contents:
            return findings
        
        stack = [(item, "") for item in contents]
        while stack:
            item, current_path = stack.pop()
            if item.type == 'dir':
                sub_contents = self.github_scanner.get_repo_contents(
                    repo_full_name, 
                    path=item.path, 
                    branch=branch
                )
                for sub in sub_contents:
                    stack.append((sub, item.path))
            elif item.type == 'file':
                file_path = item.path
                if not self.detector.should_scan_file(file_path):
                    continue
                content = self.github_scanner.get_file_content(repo_full_name, file_path, branch)
                if content:
                    file_findings = self.detector.detect_secrets_in_text(content, file_path)
                    for f in file_findings:
                        f['repo_url'] = repo_info['html_url']
                        f['repo_name'] = repo_full_name
                    findings.extend(file_findings)
        return findings

    def _scan_repo_list(self, repos: List[Dict], scan_type: str) -> str:
        all_findings = []
        for repo in repos:
            findings = self._scan_repository(repo, scan_type)
            all_findings.extend(findings)
            self.scan_history.mark_as_scanned(repo['full_name'], len(findings), scan_type)
        return self.report_generator.generate_report(
            all_findings,
            datetime.fromtimestamp(self.scan_start_time),
            scan_type=scan_type
        )

    def _check_timeout(self, current_idx: int, total_repos: int) -> bool:
        elapsed = time.time() - self.scan_start_time
        if elapsed > 55 * 60:
            print(f"⏰ 扫描超时（已运行 {elapsed/60:.1f} 分钟）")
            print(f"✅ 已完成 {current_idx}/{total_repos} 个仓库的扫描")
            return True
        return False
