#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_method_tampering(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for method tampering
        test_cases = [
            {
                'name': 'Non-standard method',
                'method': 'FAKE',
                'headers': {'X-HTTP-Method-Override': 'GET'}
            },
            {
                'name': 'Method override headers',
                'method': 'POST',
                'headers': {'X-HTTP-Method': 'PUT'}
            },
            {
                'name': 'Multiple method headers',
                'method': 'GET',
                'headers': {
                    'X-HTTP-Method-Override': 'DELETE',
                    'X-Method-Override': 'PUT'
                }
            },
            {
                'name': 'Method tunneling',
                'method': 'POST',
                'headers': {'X-Original-Method': 'CONNECT'}
            }
        ]
        
        # Get baseline response
        base_response = requests.request(method, test_url, timeout=5)
        
        for test in test_cases:
            try:
                response = requests.request(
                    test['method'],
                    test_url,
                    headers=test['headers'],
                    timeout=5
                )
                
                if is_method_tampering_vulnerable(response, base_response, test):
                    findings.append({
                        "type": "Method Tampering",
                        "detail": f"Potential {test['name']} vulnerability",
                        "evidence": {
                            "url": test_url,
                            "method": test['method'],
                            "override_headers": test['headers'],
                            "status_code": response.status_code,
                            "response_headers": dict(response.headers),
                            "response": response.text[:200]
                        }
                    })
                    
            except requests.exceptions.RequestException:
                continue
                
    except Exception as e:
        print(f"Error in method tampering check: {str(e)}")
    
    return findings

def is_method_tampering_vulnerable(response: requests.Response, base_response: requests.Response, test: Dict) -> bool:
    # Check for method tampering indicators
    
    # Check for successful override (different from base response)
    if response.status_code != base_response.status_code:
        # Exclude normal error responses
        if response.status_code not in [404, 405, 501]:
            return True
    
    # Check for method reflection in response
    response_text = response.text.lower()
    if test['method'].lower() in response_text:
        return True
    
    # Check for override header reflection
    for header_value in test['headers'].values():
        if header_value.lower() in response_text:
            return True
    
    # Check for error messages indicating method processing
    error_indicators = [
        'method not allowed',
        'invalid method',
        'unsupported method',
        'method override',
        'http method'
    ]
    
    if any(indicator in response_text for indicator in error_indicators):
        # Only consider if status code indicates partial success
        if response.status_code < 400:
            return True
    
    # Check for unusual success responses
    if test['method'] in ['FAKE', 'INVALID'] and response.status_code == 200:
        return True
    
    # Check for method tunneling success
    if test['name'] == 'Method tunneling' and response.status_code == 200:
        return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_method_tampering(
            "http://localhost:5000",
            "/api/test",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())