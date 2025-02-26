#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
import time
from RAGScripts.utils.logger import setup_scanner_logger

async def check_smuggling(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for HTTP request smuggling
        test_cases = [
            {
                'name': 'CL.TE vulnerability',
                'headers': {
                    'Content-Length': '4',
                    'Transfer-Encoding': 'chunked'
                },
                'body': 'GPOST / HTTP/1.1\r\n\r\n'
            },
            {
                'name': 'TE.CL vulnerability',
                'headers': {
                    'Content-Length': '6',
                    'Transfer-Encoding': 'chunked'
                },
                'body': '0\r\n\r\nX'
            },
            {
                'name': 'TE.TE vulnerability',
                'headers': {
                    'Transfer-Encoding': 'chunked',
                    'Transfer-encoding': 'identity'
                },
                'body': '0\r\n\r\n'
            }
        ]
        
        for test in test_cases:
            try:
                # First request to set up potential smuggling
                headers = {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    **test['headers']
                }
                
                response1 = requests.request(
                    method,
                    test_url,
                    headers=headers,
                    data=test['body'],
                    timeout=5
                )
                
                # Second request to detect timing differences
                time.sleep(1)
                start_time = time.time()
                response2 = requests.get(test_url, timeout=5)
                response_time = time.time() - start_time
                
                if is_smuggling_vulnerable(response1, response2, response_time):
                    findings.append({
                        "type": "HTTP Request Smuggling",
                        "detail": f"Potential {test['name']}",
                        "evidence": {
                            "url": test_url,
                            "headers": test['headers'],
                            "response_time": response_time,
                            "status_codes": [response1.status_code, response2.status_code],
                            "responses": [response1.text[:200], response2.text[:200]]
                        }
                    })
                    
            except requests.exceptions.RequestException:
                continue
                
    except Exception as e:
        print(f"Error in smuggling check: {str(e)}")
    
    return findings

def is_smuggling_vulnerable(response1: requests.Response, response2: requests.Response, response_time: float) -> bool:
    # Check for smuggling indicators
    
    # Timing-based detection
    if response_time > 3.0:  # Unusual delay might indicate queued request
        return True
    
    # Status code anomalies
    if response1.status_code != response2.status_code:
        return True
    
    # Response size anomalies
    if abs(len(response1.content) - len(response2.content)) > 100:
        return True
    
    # Check for error messages that might indicate request parsing issues
    error_indicators = [
        'bad request',
        'invalid request',
        'parse error',
        'malformed request',
        'protocol error'
    ]
    
    response_text = (response1.text + response2.text).lower()
    if any(indicator in response_text for indicator in error_indicators):
        return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_smuggling(
            "http://localhost:5000",
            "/api/test",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())