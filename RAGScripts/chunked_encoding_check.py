#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
import time
from RAGScripts.utils.logger import setup_scanner_logger

async def check_chunked_encoding(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for chunked encoding vulnerabilities
        test_cases = [
            {
                'name': 'Basic chunked encoding',
                'headers': {
                    'Transfer-Encoding': 'chunked'
                },
                'body': '4\r\ntest\r\n0\r\n\r\n'
            },
            {
                'name': 'Malformed chunk size',
                'headers': {
                    'Transfer-Encoding': 'chunked'
                },
                'body': 'x\r\nmalformed\r\n0\r\n\r\n'
            },
            {
                'name': 'Multiple chunk sizes',
                'headers': {
                    'Transfer-Encoding': 'chunked'
                },
                'body': '3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n'
            },
            {
                'name': 'Oversized chunk',
                'headers': {
                    'Transfer-Encoding': 'chunked'
                },
                'body': 'FFFFFFFF\r\noverflow\r\n0\r\n\r\n'
            }
        ]
        
        for test in test_cases:
            try:
                headers = {
                    'Content-Type': 'application/json',
                    **test['headers']
                }
                
                # First request with chunked encoding
                response1 = requests.request(
                    method,
                    test_url,
                    headers=headers,
                    data=test['body'],
                    timeout=5
                )
                
                # Second request to check for delayed effects
                time.sleep(1)
                response2 = requests.get(test_url, timeout=5)
                
                if is_chunked_encoding_vulnerable(response1, response2, test):
                    findings.append({
                        "type": "Chunked Encoding",
                        "detail": f"Potential {test['name']} vulnerability",
                        "evidence": {
                            "url": test_url,
                            "headers": test['headers'],
                            "body": test['body'],
                            "status_codes": [response1.status_code, response2.status_code],
                            "responses": [response1.text[:200], response2.text[:200]]
                        }
                    })
                    
            except requests.exceptions.RequestException:
                continue
                
    except Exception as e:
        print(f"Error in chunked encoding check: {str(e)}")
    
    return findings

def is_chunked_encoding_vulnerable(response1: requests.Response, response2: requests.Response, test: Dict) -> bool:
    # Check for chunked encoding vulnerability indicators
    
    # Check for error responses that might indicate vulnerability
    if response1.status_code in [400, 411, 413, 500, 502]:
        return True
    
    # Check for unexpected success responses
    if test['name'] == 'Malformed chunk size' and response1.status_code == 200:
        return True
    
    # Check for response differences
    if response1.status_code != response2.status_code:
        return True
    
    # Check for error messages in response
    error_indicators = [
        'chunk size',
        'transfer-encoding',
        'malformed request',
        'invalid chunk',
        'protocol error'
    ]
    
    response_text = (response1.text + response2.text).lower()
    if any(indicator in response_text for indicator in error_indicators):
        return True
    
    # Check for unusual response sizes
    if len(response1.content) > 1024 * 1024:  # Larger than 1MB
        return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_chunked_encoding(
            "http://localhost:5000",
            "/api/test",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())