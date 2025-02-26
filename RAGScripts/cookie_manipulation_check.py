#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_cookie_manipulation(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        original_cookies = initial_response.cookies
        
        # Test cases for cookie manipulation
        test_cases = [
            {
                'name': 'Cookie injection',
                'cookies': {
                    'session': 'test\';document.cookie="injected=true";//'
                }
            },
            {
                'name': 'Cookie attributes',
                'cookies': {
                    'session': 'test; secure=false; httpOnly=false'
                }
            },
            {
                'name': 'Multiple cookie values',
                'cookies': {
                    'session': ['value1', 'value2']
                }
            },
            {
                'name': 'Cookie overflow',
                'cookies': {
                    'session': 'A' * 4096  # Large cookie value
                }
            }
        ]
        
        for test in test_cases:
            try:
                response = requests.request(
                    method,
                    test_url,
                    cookies=test['cookies'],
                    timeout=5
                )
                
                if is_cookie_manipulation_vulnerable(response, original_cookies, test):
                    findings.append({
                        "type": "Cookie Manipulation",
                        "detail": f"Potential {test['name']} vulnerability",
                        "evidence": {
                            "url": test_url,
                            "injected_cookies": test['cookies'],
                            "status_code": response.status_code,
                            "response_cookies": dict(response.cookies),
                            "response": response.text[:200]
                        }
                    })
                    
            except requests.exceptions.RequestException:
                continue
                
    except Exception as e:
        print(f"Error in cookie manipulation check: {str(e)}")
    
    return findings

def is_cookie_manipulation_vulnerable(response: requests.Response, original_cookies: requests.cookies.RequestsCookieJar, test: Dict) -> bool:
    # Check for cookie manipulation indicators
    
    # Check for reflected cookies in response
    for cookie_value in test['cookies'].values():
        if isinstance(cookie_value, list):
            for value in cookie_value:
                if value in response.text:
                    return True
        elif isinstance(cookie_value, str):
            if cookie_value in response.text:
                return True
    
    # Check for successful cookie injection
    if test['name'] == 'Cookie injection':
        if 'injected' in response.cookies:
            return True
        if 'document.cookie' in response.text:
            return True
    
    # Check for cookie attribute manipulation
    if test['name'] == 'Cookie attributes':
        for cookie in response.cookies:
            if not cookie.secure or not cookie.has_nonstandard_attr('httpOnly'):
                return True
    
    # Check for multiple cookie handling
    if test['name'] == 'Multiple cookie values':
        cookie_count = len(response.cookies)
        if cookie_count > len(original_cookies):
            return True
    
    # Check for cookie overflow handling
    if test['name'] == 'Cookie overflow':
        if response.status_code == 200:
            return True
    
    # Check for error messages indicating cookie processing issues
    error_indicators = [
        'invalid cookie',
        'malformed cookie',
        'cookie error',
        'cookie overflow',
        'cookie injection'
    ]
    
    if any(indicator in response.text.lower() for indicator in error_indicators):
        if response.status_code < 400:
            return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_cookie_manipulation(
            "http://localhost:5000",
            "/api/test",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())