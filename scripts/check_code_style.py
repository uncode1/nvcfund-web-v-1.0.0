"""
Script to check code style and security across the entire project.
"""

import os
from utils.code_style_checker import CodeStyleChecker

def main():
    """Main function to check code style."""
    # Initialize checker
    checker = CodeStyleChecker({})
    
    # Get project root directory
    root_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Check all Python files
    print("Checking code style and security...")
    results = checker.check_directory(root_dir)
    
    # Print summary
    print("\nSummary:")
    print(f"Total files: {results['total_files']}")
    print(f"Files checked: {len(results['files_checked'])}")
    
    # Print issues if any
    if results['issues']:
        print("\nIssues found:")
        for file, issues in results['issues'].items():
            print(f"\nFile: {file}")
            for category, issue_list in issues.items():
                if issue_list:
                    print(f"\n{category.upper()} issues:")
                    for issue in issue_list:
                        print(f"  - {issue}")
    else:
        print("\nNo issues found!")

if __name__ == '__main__':
    main()
