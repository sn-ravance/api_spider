#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_header_injection(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for header injection
        test_cases = [
            {
                'name': 'CRLF injection',
                'headers': {
                    'X-Custom': 'test\r\nSet-Cookie: injected=true'
                }
            },
            {
                'name': 'Header line folding',
                'headers': {
                    'X-Custom': 'test\r\n test'
                }
            },
            {
                'name': 'Multiple header values',
                'headers': {
                    'X-Custom': ['value1', 'value2']
                }
            },
            {
                'name': 'Special characters',
                'headers': {
                    'X-Custom': '"><script>alert(1)</script>'
                }
            }
        ]
        
        for test in test_cases:
            try:
                response = requests.request(
                    method,
                    test_url,
                    headers=test['headers'],
                    timeout=5
                )
                
                if is_header_injection_vulnerable(response, test):
                    findings.append({
                        "type": "Header Injection",
                        "detail": f"Potential {test['name']} vulnerability",
                        "evidence": {
                            "url": test_url,
                            "injected_headers": test['headers'],
                            "status_code": response.status_code,
                            "response_headers": dict(response.headers),
                            "response": response.text[:200]
                        }
                    })
                    
            except requests.exceptions.RequestException:
                continue
                
    except Exception as e:
        print(f"Error in header injection check: {str(e)}")
    
    return findings

def is_header_injection_vulnerable(response: requests.Response, test: Dict) -> bool:
    # Check for header injection indicators
    
    # Check for reflected headers in response
    for header_value in test['headers'].values():
        if isinstance(header_value, list):
            for value in header_value:
                if value in response.text:
                    return True
        elif isinstance(header_value, str):
            if header_value in response.text:
                return True
    
    # Check for successful CRLF injection
    if test['name'] == 'CRLF injection':
        if 'injected' in response.cookies:
            return True
        if 'Set-Cookie' in response.text:
            return True
    
    # Check for header folding success
    if test['name'] == 'Header line folding':
        for header, value in response.headers.items():
            if '\n' in value or '\r' in value:
                return True
    
    # Check for multiple header handling
    if test['name'] == 'Multiple header values':
        header_count = len([h for h in response.headers.values() if h])
        if header_count > len(set(response.headers.values())):
            return True
    
    # Check for XSS via headers
    if test['name'] == 'Special characters':
        if '<script>' in response.text:
            return True
    
    # Check for error messages indicating header processing issues
    error_indicators = [
        'invalid header',
        'malformed header',
        'header injection',
        'illegal character'
    ]
    
    if any(indicator in response.text.lower() for indicator in error_indicators):
        if response.status_code < 400:
            return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_header_injection(
            "http://localhost:5000",
            "/api/test",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())