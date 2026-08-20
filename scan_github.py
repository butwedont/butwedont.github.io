#!/usr/bin/env python3
import argparse
import os
from scanner import CloudScanner

def main():
    parser = argparse.ArgumentParser(description="GitHub AI API Key Scanner")
    parser.add_argument("--auto", action="store_true", help="自动搜索AI项目")
    parser.add_argument("--max-repos", type=int, default=50, help="最大扫描仓库数")
    parser.add_argument("--user", type=str, help="扫描指定用户")
    parser.add_argument("--org", type=str, help="扫描指定组织")
    parser.add_argument("--repo", type=str, help="扫描单个仓库 (格式: owner/repo)")
    parser.add_argument("--token", type=str, help="GitHub Token (也可通过环境变量GITHUB_TOKEN设置)")
    args = parser.parse_args()

    token = args.token or os.getenv('GITHUB_TOKEN')
    if not token:
        print("❌ 错误: 需要GitHub Token。请设置环境变量GITHUB_TOKEN或使用--token参数。")
        return

    scanner = CloudScanner(token)

    if args.auto:
        scanner.scan_ai_projects(max_repos=args.max_repos)
    elif args.user:
        scanner.scan_user_repos(args.user, max_repos=args.max_repos)
    elif args.org:
        scanner.scan_org_repos(args.org, max_repos=args.max_repos)
    elif args.repo:
        scanner.scan_single_repo(args.repo)
    else:
        print("请指定扫描模式: --auto, --user, --org 或 --repo")
        parser.print_help()

if __name__ == "__main__":
    main()
