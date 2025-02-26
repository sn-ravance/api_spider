#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
from collections import OrderedDict
from RAGScripts.utils.logger import setup_scanner_logger

async def check_header_order(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for header order manipulation
        test_cases = [
            {
                'name': 'Standard order',
                'headers': OrderedDict([
                    ('Host', target_url),
                    ('Content-Type', 'application/json'),
                    ('Accept', '*/*')
                ])
            },
            {
                'name': 'Reversed order',
                'headers': OrderedDict([
                    ('Accept', '*/*'),
                    ('Content-Type', 'application/json'),
                    ('Host', target_url)
                ])
            },
            {
                'name': 'Duplicate headers',
                'headers': OrderedDict([
                    ('Host', target_url),
                    ('Accept', '*/*'),
                    ('Accept', 'application/json'),
                    ('Content-Type', 'application/json')
                ])
            },
            {
                'name': 'Mixed case headers',
                'headers': OrderedDict([
                    ('host', target_url),
                    ('CONTENT-TYPE', 'application/json'),
                    ('Accept', '*/*')
                ])
            }
        ]
        
        base_response = requests.request(method, test_url, timeout=5)
        
        for test in test_cases:
            try:
                response = requests.request(
                    method,
                    test_url,
                    headers=test['headers'],
                    timeout=5
                )
                
                if is_header_order_vulnerable(response, base_response, test):
                    findings.append({
                        "type": "Header Order Manipulation",
                        "detail": f"Potential vulnerability with {test['name']}",
                        "evidence": {
                            "url": test_url,
                            "headers": dict(test['headers']),
                            "status_code": response.status_code,
                            "response_headers": dict(response.headers),
                            "response": response.text[:200]
                        }
                    })
                    
            except requests.exceptions.RequestException:
                continue
                
    except Exception as e:
        print(f"Error in header order check: {str(e)}")
    
    return findings

def is_header_order_vulnerable(response: requests.Response, base_response: requests.Response, test: Dict) -> bool:
    # Check for header order vulnerability indicators
    
    # Different status code might indicate processing differences
    if response.status_code != base_response.status_code:
        return True
    
    # Check for unusual response headers
    if len(response.headers) != len(base_response.headers):
        return True
    
    # Check for error messages in response
    error_indicators = [
        'invalid header',
        'malformed header',
        'duplicate header',
        'header order',
        'protocol violation'
    ]
    
    response_text = response.text.lower()
    if any(indicator in response_text for indicator in error_indicators):
        return True
    
    # Check for reflected headers in response
    for header_name in test['headers'].keys():
        if header_name.lower() in response_text:
            return True
    
    # Check for significant response size differences
    if abs(len(response.content) - len(base_response.content)) > 100:
        return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_header_order(
            "http://localhost:5000",
            "/api/test",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())