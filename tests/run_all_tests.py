"""
Test runner script that executes all test suites.

This script runs:
1. Unit tests
2. Integration tests
3. Performance tests
4. Security tests
5. Code style checks
"""

import os
import sys
import pytest
import logging
import json
import subprocess
from datetime import datetime
from typing import Dict, Any, Optional
from utils.logging.config import LoggingConfig
from utils.performance.monitor import ResourceMonitor
import xml.etree.ElementTree as ET
import signal
import time
import psutil

def run_test_with_timeout(test_name: str, test_file: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Run a single test with timeout handling."""
    logger = LoggingConfig(config).get_module_logger('test_runner')
    
    xml_report = f"test_results_{test_name.lower()}.xml"
    progress_file = f"progress_{test_name.lower()}.txt"
    
    # Create progress file
    with open(progress_file, 'w') as f:
        f.write(f"Test started at {datetime.now().isoformat()}\n")
    
    # Prepare command
    cmd = [
        sys.executable, '-m', 'pytest',
        os.path.join(config['test_dir'], test_file),
        '-v',
        '--tb=short',
        '--junit-xml', xml_report,
        '--cov=.',
        '--cov-report=term-missing'
    ]
    
    logger.info(f"\nStarting {test_name} tests...")
    logger.info(f"Command: {' '.join(cmd)}")
    logger.info(f"Timeout: {config['test_timeout']} seconds")
    
    try:
        # Start test process
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid  # Create new process group
        )
        
        # Monitor process
        start_time = time.time()
        last_output = ""
        
        while time.time() - start_time < config['test_timeout']:
            # Check if process has finished
            if process.poll() is not None:
                break
                
            # Read output
            if process.stdout:
                output = process.stdout.read().decode('utf-8')
                if output:
                    last_output = output
                    logger.info(f"Test output: {output}")
                    with open(progress_file, 'a') as f:
                        f.write(output)
            
            # Check resource usage
            try:
                process_info = psutil.Process(process.pid)
                memory = process_info.memory_info().rss / (1024 * 1024)  # Convert to MB
                cpu = process_info.cpu_percent(interval=0.1)
                logger.info(f"Resource usage - CPU: {cpu}%, Memory: {memory:.2f}MB")
            except psutil.NoSuchProcess:
                break
            
            time.sleep(config['check_interval'])
        
        # Check if process is still running
        if process.poll() is None:
            logger.error(f"Test exceeded timeout ({config['test_timeout']}s), terminating...")
            try:
                # Kill the entire process group
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logger.error("Process did not terminate, using SIGKILL")
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                process.wait()
            
            raise Exception(f"Test timed out after {config['test_timeout']} seconds")
        
        # Get output
        stdout, stderr = process.communicate()
        if stderr:
            logger.error(f"Test error output: {stderr.decode('utf-8')}")
            
        if process.returncode != 0:
            raise Exception(f"Test failed with return code {process.returncode}")
            
        # Get test results
        test_results = _get_test_results(xml_report)
        
        # Log completion
        logger.info(f"\n{test_name} tests completed successfully!")
        logger.info(f"Passed: {test_results['passed']}")
        logger.info(f"Failed: {test_results['failed']}")
        logger.info(f"Coverage: {test_results['coverage']}%")
        
        with open(progress_file, 'a') as f:
            f.write(f"Test completed successfully at {datetime.now().isoformat()}\n")
            f.write(f"Passed: {test_results['passed']}\n")
            f.write(f"Failed: {test_results['failed']}\n")
            f.write(f"Coverage: {test_results['coverage']}%\n")
            
        return {
            'results': test_results,
            'status': 'completed',
            'error': None,
            'output': stdout.decode('utf-8')
        }
        
    except Exception as e:
        logger.error(f"\n{test_name} tests failed: {str(e)}")
        
        with open(progress_file, 'a') as f:
            f.write(f"Test failed at {datetime.now().isoformat()}\n")
            f.write(f"Error: {str(e)}\n")
        
        return {
            'results': {
                'total': 0,
                'passed': 0,
                'failed': 1,
                'coverage': 0.0
            },
            'status': 'failed',
            'error': str(e),
            'output': ''
        }

def test_all():
    """Run all test suites."""
    config = {
        'test_dir': 'tests',
        'log_level': 'INFO',
        'log_file': f'test_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
        'test_timeout': 300,  # 5 minutes
        'check_interval': 5,  # Check progress every 5 seconds
        'resource_monitor_config': {
            'sample_interval': 0.1,
            'warning_thresholds': {
                'cpu': 80.0,
                'memory': 85.0,
                'disk_io': 1000000,
                'network_io': 10000000
            }
        }
    }
    
    logger = LoggingConfig(config).get_module_logger('test_runner')
    monitor = ResourceMonitor(config['resource_monitor_config'])
    
    # Set up test environment
    os.makedirs('test_files', exist_ok=True)
    os.makedirs('test_logs', exist_ok=True)
    monitor.start_monitoring()
    logger.info("Starting test suite execution")
    
    try:
        # Initialize results dict
        results = {
            'total': 0,
            'passed': 0,
            'failed': 0,
            'coverage': 0.0,
            'test_results': {},
            'progress': {}
        }
        
        # List of test files to run
        test_files = [
            ('API', 'test_api.py'),
            ('Models', 'test_models.py'),
            ('Performance', 'performance_test.py'),
            ('Code Style', 'test_code_style.py'),
            ('Config', 'test_config.py'),
            ('Logging', 'test_logging.py'),
            ('Report', 'test_report.py')
        ]
        
        # Run each test
        for test_name, test_file in test_files:
            try:
                test_result = run_test_with_timeout(test_name, test_file, config)
                
                # Update results
                results['test_results'][test_name] = test_result['results']
                results['progress'][test_name] = {
                    'start_time': datetime.now().isoformat(),
                    'end_time': datetime.now().isoformat(),
                    'status': test_result['status'],
                    'error': test_result['error'],
                    'output': test_result['output']
                }
                
                if test_result['status'] == 'completed':
                    results['total'] += test_result['results']['total']
                    results['passed'] += test_result['results']['passed']
                    results['failed'] += test_result['results']['failed']
                    results['coverage'] = max(results['coverage'], test_result['results']['coverage'])
                else:
                    results['failed'] += 1
                    
            except Exception as e:
                logger.error(f"{test_name} tests failed: {str(e)}")
                results['failed'] += 1
                results['test_results'][test_name] = {
                    'total': 0,
                    'passed': 0,
                    'failed': 1,
                    'coverage': 0.0
                }
                results['progress'][test_name] = {
                    'start_time': datetime.now().isoformat(),
                    'end_time': datetime.now().isoformat(),
                    'status': 'failed',
                    'error': str(e),
                    'output': ''
                }
        
        # Generate final report
        resource_metrics = monitor.get_metrics_summary()
        report = {
            'timestamp': datetime.now().isoformat(),
            'test_results': results['test_results'],
            'progress': results['progress'],
            'summary': {
                'total': results['total'],
                'passed': results['passed'],
                'failed': results['failed'],
                'coverage': results['coverage'],
                'success_rate': (results['passed'] / results['total']) * 100 if results['total'] > 0 else 0,
                'failure_rate': (results['failed'] / results['total']) * 100 if results['total'] > 0 else 0,
                'resource_usage': resource_metrics
            }
        }
        
        # Save report
        with open('test_report.json', 'w') as f:
            json.dump(report, f, indent=4)
        
        # Log summary
        logger.info("\nTest Suite Summary:")
        logger.info(f"Total Tests: {results['total']}")
        logger.info(f"Passed: {results['passed']}")
        logger.info(f"Failed: {results['failed']}")
        logger.info(f"Coverage: {results['coverage']}%")
        logger.info(f"Success Rate: {report['summary']['success_rate']}%")
        logger.info(f"Failure Rate: {report['summary']['failure_rate']}%")
        logger.info(f"Resource Usage: {resource_metrics}")
        
        # Raise exception if any tests failed
        if results['failed'] > 0:
            raise Exception(f"Test suite failed: {results['failed']} tests failed")
            
        return report
    except Exception as e:
        logger.error(f"Test execution failed: {str(e)}")
        raise
    finally:
        # Clean up
        monitor.stop_monitoring()
        logger.info("Test suite execution completed")

def _get_test_results(xml_report: str):
    """Get test results from XML report."""
    try:
        if not os.path.exists(xml_report):
            raise FileNotFoundError(f"Test results file not found: {xml_report}")
            
        tree = ET.parse(xml_report)
        root = tree.getroot()
        
        total = 0
        passed = 0
        failed = 0
        
        for test_suite in root.findall('testsuite'):
            total += int(test_suite.get('tests', 0))
            passed += int(test_suite.get('passed', 0))
            failed += int(test_suite.get('failures', 0))
            
        # Get coverage from .coverage file
        try:
            with open('.coverage', 'r') as f:
                coverage = float(f.read().strip())
        except (FileNotFoundError, ValueError):
            coverage = 0.0
            
        return {
            'total': total,
            'passed': passed,
            'failed': failed,
            'coverage': coverage
        }
    except Exception as e:
        logger = LoggingConfig({'log_level': 'INFO'}).get_module_logger('test_runner')
        logger.error(f"Error getting test results for {xml_report}: {str(e)}")
        return {
            'total': 0,
            'passed': 0,
            'failed': 1,
            'coverage': 0.0
        }





if __name__ == '__main__':
    test_all()
