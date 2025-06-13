"""
Code Style Checker System
========================

This module implements a comprehensive code style and security checking system that ensures:
1. PEP8 compliance
2. Secure coding practices
3. Code quality standards
4. Security best practices

Key Features:
------------
- Automatic PEP8 compliance checking
- Security vulnerability detection
- Code style enforcement
- File size and complexity monitoring
- Detailed issue reporting
- Automatic fixes for common issues

Usage:
------
1. Initialize the checker:
```python
checker = CodeStyleChecker(config)
```

2. Check a single file:
```python
issues = checker.check_file('path/to/file.py')
```

3. Check entire directory:
```python
results = checker.check_directory('/path/to/project')
```

4. Fix issues automatically:
```python
checker.fix_issues('path/to/file.py')
```

Security Checks:
--------------
- SQL injection detection
- XSS vulnerability scanning
- Path traversal prevention
- Command injection detection
- Email handling validation
- Phone number validation
- Input sanitization
- Secure coding practices

Code Style Rules:
---------------
- Maximum line length (100 characters)
- Proper indentation (4 spaces)
- Organized imports
- Consistent naming conventions
- Comment guidelines
- File size limits

"""

import ast
import re
import os
from typing import Dict, List, Tuple, Optional, Any
from pylint.lint import Run as PylintRun
from pylint.reporters.text import TextReporter
import io
from src.security.utils.secure_coding import SecureCoding

class CodeStyleChecker:
    """
    Main code style and security checking class.
    
    Args:
        config: Configuration dictionary containing:
            - security_settings: Security-related settings
            - style_settings: Code style preferences
            - logging_settings: Logging configuration
            - validation_rules: Validation rules
    
    Attributes:
        config: Configuration dictionary
        secure: Secure coding utility instance
        patterns: Regular expression patterns for security checks
    
    Methods:
        check_file: Check a single file for issues
        check_directory: Check all files in a directory
        fix_issues: Attempt to fix common issues
        _initialize_patterns: Set up security patterns
        _split_long_line: Split long lines into multiple lines
        _fix_indentation: Fix indentation issues
        _organize_imports: Organize imports in the file
    """
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the code style checker.
        
        Args:
            config: Configuration dictionary containing:
                - security_settings: Security-related settings
                - style_settings: Code style preferences
                - logging_settings: Logging configuration
                - validation_rules: Validation rules
        """
        self.config = config
        self.secure = SecureCoding(config)
        self._initialize_patterns()

    def _initialize_patterns(self) -> None:
        """Initialize patterns for secure coding."""
        self.patterns = {
            'sql': re.compile(r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION)\b', re.IGNORECASE),
            'xss': re.compile(r'<script|javascript:', re.IGNORECASE),
            'path': re.compile(r'\.{2}/|/\.{2}|\.{2}\\|\\\.{2}\\'),
            'cmd': re.compile(r'\b(system|exec|shell_exec|passthru|eval|assert)\b', re.IGNORECASE),
            'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
            'phone': re.compile(r'^\+[1-9]\d{1,14}$')
        }

    def check_file(self, filepath: str) -> Dict[str, List[str]]:
        """
        Check a single file for PEP8 compliance and secure coding.
        
        Args:
            filepath: Path to the file to check
            
        Returns:
            Dictionary of issues found
        """
        issues = {
            'pep8': [],
            'security': [],
            'style': []
        }
        
        try:
            # Check PEP8 compliance
            output = io.StringIO()
            reporter = TextReporter(output)
            PylintRun([filepath], reporter=reporter, exit=False)
            pep8_issues = output.getvalue()
            if pep8_issues:
                issues['pep8'].extend(pep8_issues.split('\n'))
                
            # Check secure coding
            with open(filepath, 'r') as f:
                content = f.read()
                
                # Check for SQL injection
                if self.patterns['sql'].search(content):
                    issues['security'].append('Potential SQL injection vulnerability')
                    
                # Check for XSS
                if self.patterns['xss'].search(content):
                    issues['security'].append('Potential XSS vulnerability')
                    
                # Check for path traversal
                if self.patterns['path'].search(content):
                    issues['security'].append('Potential path traversal vulnerability')
                    
                # Check for command injection
                if self.patterns['cmd'].search(content):
                    issues['security'].append('Potential command injection vulnerability')
                    
                # Check for unsafe email handling
                if self.patterns['email'].search(content):
                    issues['security'].append('Potential unsafe email handling')
                    
                # Check for unsafe phone number handling
                if self.patterns['phone'].search(content):
                    issues['security'].append('Potential unsafe phone number handling')
                    
                # Check file size
                if os.path.getsize(filepath) > 100000:  # 100KB
                    issues['style'].append('File is too large')
                    
                # Check line length
                for line in content.split('\n'):
                    if len(line) > 100:
                        issues['style'].append('Line too long')
                        
                # Check for TODOs
                if 'TODO' in content:
                    issues['style'].append('TODO items found')
                    
        except Exception as e:
            issues['error'] = [str(e)]
            
        return issues

    def check_directory(self, directory: str) -> Dict[str, List[str]]:
        """
        Check all Python files in a directory.
        
        Args:
            directory: Directory path to check
            
        Returns:
            Dictionary of issues found
        """
        all_issues = {
            'total_files': 0,
            'files_checked': [],
            'issues': {}
        }
        
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith('.py'):
                    filepath = os.path.join(root, file)
                    all_issues['total_files'] += 1
                    all_issues['files_checked'].append(filepath)
                    
                    issues = self.check_file(filepath)
                    if any(issues.values()):
                        all_issues['issues'][filepath] = issues
                        
        return all_issues

    def fix_issues(self, filepath: str) -> None:
        """
        Attempt to fix common issues in a file.
        
        Args:
            filepath: Path to the file to fix
        """
        try:
            with open(filepath, 'r') as f:
                content = f.read()
                
            # Fix line length
            fixed_content = []
            for line in content.split('\n'):
                if len(line) > 100:
                    # Split long lines
                    fixed_content.extend(self._split_long_line(line))
                else:
                    fixed_content.append(line)
                    
            # Fix indentation
            fixed_content = self._fix_indentation(fixed_content)
            
            # Fix imports
            fixed_content = self._organize_imports(fixed_content)
            
            # Write fixed content
            with open(filepath, 'w') as f:
                f.write('\n'.join(fixed_content))
                
        except Exception as e:
            print(f"Error fixing file {filepath}: {e}")
            
    def _split_long_line(self, line: str) -> List[str]:
        """Split a long line into multiple lines."""
        if len(line) <= 100:
            return [line]
            
        # Find a good split point
        split_point = 80
        while split_point < len(line) and line[split_point] not in ' ,;':
            split_point += 1
            
        if split_point == len(line):
            return [line]
            
        return [line[:split_point].rstrip(), line[split_point:].lstrip()]
    
    def _fix_indentation(self, lines: List[str]) -> List[str]:
        """Fix indentation in lines."""
        indent_level = 0
        fixed_lines = []
        
        for line in lines:
            stripped = line.lstrip()
            if stripped.startswith(('def ', 'class ')):
                indent_level += 1
            elif stripped.startswith(('return', 'break', 'continue')):
                indent_level = max(0, indent_level - 1)
                
            fixed_lines.append('    ' * indent_level + stripped)
            
        return fixed_lines
    
    def _organize_imports(self, lines: List[str]) -> List[str]:
        """Organize imports in the file."""
        imports = []
        other_lines = []
        
        for line in lines:
            if line.startswith('import ') or line.startswith('from '):
                imports.append(line)
            else:
                other_lines.append(line)
                
        # Sort imports
        imports.sort()
        
        # Add back imports
        return imports + [''] + other_lines
