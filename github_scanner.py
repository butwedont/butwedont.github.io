import os
from github import Github, GithubException
from typing import List, Dict, Callable, Optional

class GitHubScanner:
    def __init__(self, token: str = None):
        self.token = token or os.getenv('GITHUB_TOKEN')
        if not self.token:
            raise ValueError("GitHub token is required. Set GITHUB_TOKEN environment variable.")
        self.g = Github(self.token)

    def search_ai_repos(self, max_repos: int = 50, skip_filter: Optional[Callable] = None) -> List[Dict]:
        query = 'openai OR anthropic OR gemini OR "api key" OR "API_KEY" OR "api_key" in:readme,description'
        try:
            result = self.g.search_repositories(query, sort='updated', order='desc')
            repos = []
            for repo in result[:max_repos]:
                if skip_filter and skip_filter(repo.full_name):
                    continue
                repos.append({
                    'full_name': repo.full_name,
                    'html_url': repo.html_url,
                    'clone_url': repo.clone_url,
                    'default_branch': repo.default_branch,
                    'description': repo.description or '',
                })
            return repos
        except GithubException as e:
            print(f"❌ GitHub搜索失败: {e}")
            return []

    def get_repo_contents(self, repo_full_name: str, path: str = "", branch: str = None) -> List:
        repo = self.g.get_repo(repo_full_name)
        try:
            contents = repo.get_contents(path, ref=branch)
            return contents
        except GithubException:
            return []

    def get_file_content(self, repo_full_name: str, file_path: str, branch: str = None) -> str:
        repo = self.g.get_repo(repo_full_name)
        try:
            content = repo.get_contents(file_path, ref=branch)
            if content.encoding == 'base64':
                import base64
                decoded = base64.b64decode(content.content).decode('utf-8', errors='ignore')
                return decoded
            return ''
        except Exception:
            return ''
