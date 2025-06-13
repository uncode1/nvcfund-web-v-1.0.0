"""
Test suite for code style checker.

This test suite ensures that the code style checker:
1. Properly enforces PEP8 compliance
2. Detects security vulnerabilities
3. Fixes common code style issues
4. Provides accurate issue reporting
5. Handles edge cases correctly
"""

import os
import unittest
from utils.code_style_checker import CodeStyleChecker


class TestCodeStyleChecker(unittest.TestCase):
    """
    Test cases for the code style checker.
    
    Tests verify:
    - PEP8 compliance checking
    - Security vulnerability detection
    - Code style enforcement
    - Issue reporting
    - Automatic fixes
    """
    
    def setUp(self):
        """Set up test environment."""
        self.checker = CodeStyleChecker({})
        self.test_dir = os.path.join(os.path.dirname(__file__), 'test_files')
        os.makedirs(self.test_dir, exist_ok=True)
        
    def tearDown(self):
        """Clean up test files."""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_pep8_compliance(self):
        """Test PEP8 compliance checking."""
        # Create test file with PEP8 violations
        test_file = os.path.join(self.test_dir, 'test_pep8.py')
        with open(test_file, 'w') as f:
            f.write("""
def test():
    if True:print('Hello')
""")
        
        # Check file
        issues = self.checker.check_file(test_file)
        
        # Verify issues found
        self.assertIn('pep8', issues)
        self.assertGreater(len(issues['pep8']), 0)
    
    def test_security_vulnerabilities(self):
        """Test security vulnerability detection."""
        # Create test file with security issues
        test_file = os.path.join(self.test_dir, 'test_security.py')
        with open(test_file, 'w') as f:
            f.write("""
def unsafe_sql(query):
    return f"SELECT * FROM users WHERE name = '{query}'"

html = '<script>alert("XSS")</script>'
""")
        
        # Check file
        issues = self.checker.check_file(test_file)
        
        # Verify security issues found
        self.assertIn('security', issues)
        self.assertIn('SQL injection', issues['security'][0])
        self.assertIn('XSS', issues['security'][1])
    
    def test_code_style_fixes(self):
        """Test automatic code style fixes."""
        # Create test file with style issues
        test_file = os.path.join(self.test_dir, 'test_style.py')
        with open(test_file, 'w') as f:
            f.write("""
def test():
    if True:print('Hello')
""")
        
        # Fix issues
        self.checker.fix_issues(test_file)
        
        # Verify fixes
        with open(test_file, 'r') as f:
            content = f.read()
            self.assertIn('def test():', content)
            self.assertIn('    if True:', content)
            self.assertIn('        print', content)
    
    def test_large_file_handling(self):
        """Test handling of large files."""
        # Create large test file
        test_file = os.path.join(self.test_dir, 'test_large.py')
        with open(test_file, 'w') as f:
            f.write('x = 1' * 10000)  # Create large file
        
        # Check file
        issues = self.checker.check_file(test_file)
        
        # Verify file size warning
        self.assertIn('style', issues)
        self.assertIn('File is too long', issues['style'])
    
    def test_directory_check(self):
        """Test checking entire directory."""
        # Create multiple test files
        os.makedirs(os.path.join(self.test_dir, 'test_subdir'), exist_ok=True)
        test_files = [
            os.path.join(self.test_dir, 'test1.py'),
            os.path.join(self.test_dir, 'test_subdir', 'test2.py')
        ]
        
        for file in test_files:
            with open(file, 'w') as f:
                f.write("""
def test():
    if True:print('Hello')
""")
        
        # Check directory
        results = self.checker.check_directory(self.test_dir)
        
        # Verify results
        self.assertGreater(results['total_files'], 0)
        self.assertGreater(len(results['files_checked']), 0)
        self.assertIn(test_files[0], results['issues'])
        self.assertIn(test_files[1], results['issues'])

if __name__ == '__main__':
    unittest.main()
