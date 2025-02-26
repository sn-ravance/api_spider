#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin, parse_qs, urlparse
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_cmdi(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        parsed_url = urlparse(test_url)
        query_params = parse_qs(parsed_url.query)
        
        # Command injection payloads
        payloads = [
            {
                'payload': '; sleep 5 #',
                'desc': 'Basic command injection'
            },
            {
                'payload': '| sleep 5',
                'desc': 'Pipe command injection'
            },
            {
                'payload': '`sleep 5`',
                'desc': 'Backtick command injection'
            },
            {
                'payload': '$(sleep 5)',
                'desc': 'Subshell command injection'
            },
            {
                'payload': '& ping -c 1 127.0.0.1 &',
                'desc': 'Background command injection'
            }
        ]
        
        # Test query parameters
        for param_name, param_value in query_params.items():
            for test in payloads:
                modified_params = query_params.copy()
                modified_params[param_name] = [test['payload']]
                
                try:
                    start_time = time.time()
                    response = requests.request(
                        method,
                        test_url,
                        params=modified_params,
                        headers={'Content-Type': 'application/json'},
                        timeout=10
                    )
                    response_time = time.time() - start_time
                    
                    if is_cmdi_vulnerable(response, response_time):
                        findings.append({
                            "type": "Command Injection",
                            "detail": f"{test['desc']} in parameter {param_name}",
                            "evidence": {
                                "url": test_url,
                                "parameter": param_name,
                                "payload": test['payload'],
                                "status_code": response.status_code,
                                "response_time": response_time,
                                "response": response.text[:200]
                            }
                        })
                except requests.exceptions.RequestException:
                    continue
        
        # Test request body for POST/PUT methods
        if method in ['POST', 'PUT']:
            for test in payloads:
                try:
                    start_time = time.time()
                    response = requests.request(
                        method,
                        test_url,
                        json={"command": test['payload']},
                        headers={'Content-Type': 'application/json'},
                        timeout=10
                    )
                    response_time = time.time() - start_time
                    
                    if is_cmdi_vulnerable(response, response_time):
                        findings.append({
                            "type": "Command Injection",
                            "detail": f"{test['desc']} in request body",
                            "evidence": {
                                "url": test_url,
                                "payload": test['payload'],
                                "status_code": response.status_code,
                                "response_time": response_time,
                                "response": response.text[:200]
                            }
                        })
                except requests.exceptions.RequestException:
                    continue
                
    except Exception as e:
        print(f"Error in command injection check: {str(e)}")
    
    return findings

def is_cmdi_vulnerable(response: requests.Response, response_time: float) -> bool:
    # Check for command injection indicators
    indicators = [
        '/bin/',
        '/etc/',
        'root:',
        'Permission denied',
        'command not found',
        'sh:',
        'bash:'
    ]
    
    # Check for time-based injection (sleep command)
    if response_time >= 4.5:  # Allow for network latency
        return True
        
    # Check for command output in response
    response_text = response.text.lower()
    if any(indicator.lower() in response_text for indicator in indicators):
        return True
        
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio, time
    async def test():
        result = await check_cmdi(
            "http://localhost:5000",
            "/api/execute?cmd=test",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())