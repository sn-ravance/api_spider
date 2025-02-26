#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_content_type(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for content type manipulation
        test_cases = [
            {
                'name': 'Mixed content type',
                'content_type': 'application/json; text/plain',
                'data': '{"key": "value"} plain text'
            },
            {
                'name': 'Invalid charset',
                'content_type': 'application/json; charset=invalid-charset',
                'data': '{"key": "value"}'
            },
            {
                'name': 'Multiple content types',
                'content_type': ['application/json', 'application/xml'],
                'data': '{"key": "value"}'
            },
            {
                'name': 'Malformed content type',
                'content_type': 'application/json;;;',
                'data': '{"key": "value"}'
            }
        ]
        
        # Get baseline response
        base_response = requests.request(
            method,
            test_url,
            headers={'Content-Type': 'application/json'},
            data='{"test": "baseline"}',
            timeout=5
        )
        
        for test in test_cases:
            try:
                headers = {'Content-Type': test['content_type']}
                response = requests.request(
                    method,
                    test_url,
                    headers=headers,
                    data=test['data'],
                    timeout=5
                )
                
                if is_content_type_vulnerable(response, base_response, test):
                    findings.append({
                        "type": "Content Type Manipulation",
                        "detail": f"Potential {test['name']} vulnerability",
                        "evidence": {
                            "url": test_url,
                            "content_type": test['content_type'],
                            "test_data": test['data'],
                            "status_code": response.status_code,
                            "response_headers": dict(response.headers),
                            "response": response.text[:200]
                        }
                    })
                    
            except requests.exceptions.RequestException:
                continue
                
    except Exception as e:
        print(f"Error in content type check: {str(e)}")
    
    return findings

def is_content_type_vulnerable(response: requests.Response, base_response: requests.Response, test: Dict) -> bool:
    # Check for content type manipulation indicators
    
    # Check for successful processing despite invalid content type
    if test['name'] in ['Invalid charset', 'Malformed content type']:
        if response.status_code == base_response.status_code:
            return True
    
    # Check for mixed content type processing
    if test['name'] == 'Mixed content type':
        if response.status_code == 200:
            return True
    
    # Check for multiple content type handling
    if test['name'] == 'Multiple content types':
        if response.status_code != 400:
            return True
    
    # Check for error messages in response
    error_indicators = [
        'invalid content type',
        'unsupported media type',
        'malformed content',
        'charset error',
        'parsing error'
    ]
    
    response_text = response.text.lower()
    if any(indicator in response_text for indicator in error_indicators):
        if response.status_code < 400:
            return True
    
    # Check for content type reflection
    if test['content_type'].lower() in response_text:
        return True
    
    # Check for unusual success responses
    if response.status_code == 200 and 'content-type' not in response.headers:
        return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_content_type(
            "http://localhost:5000",
            "/api/test",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())