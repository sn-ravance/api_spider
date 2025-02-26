#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
import time
from RAGScripts.utils.logger import setup_scanner_logger

async def check_cache_poisoning(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for cache poisoning
        test_cases = [
            {
                'name': 'Host header variation',
                'headers': {
                    'Host': 'evil-host.com',
                    'X-Forwarded-Host': 'evil-host.com'
                }
            },
            {
                'name': 'Cache control manipulation',
                'headers': {
                    'Cache-Control': 'public, max-age=31536000',
                    'X-Cache-Control': 'public, max-age=31536000'
                }
            },
            {
                'name': 'Vary header bypass',
                'headers': {
                    'Vary': '*',
                    'X-Vary': 'User-Agent'
                }
            },
            {
                'name': 'CDN cache poisoning',
                'headers': {
                    'X-Forwarded-For': '127.0.0.1',
                    'X-Original-URL': '/admin',
                    'X-Rewrite-URL': '/admin'
                }
            }
        ]
        
        for test in test_cases:
            try:
                # First request to potentially poison cache
                poison_response = requests.request(
                    method,
                    test_url,
                    headers=test['headers'],
                    timeout=5
                )
                
                # Second request to check if poisoning worked
                time.sleep(1)
                verify_response = requests.get(
                    test_url,
                    headers={'Cache-Control': 'no-cache'},
                    timeout=5
                )
                
                if is_cache_poisoned(poison_response, verify_response, test):
                    findings.append({
                        "type": "Cache Poisoning",
                        "detail": f"Potential {test['name']} vulnerability",
                        "evidence": {
                            "url": test_url,
                            "poisoned_headers": test['headers'],
                            "cache_headers": {
                                "poison": dict(poison_response.headers),
                                "verify": dict(verify_response.headers)
                            },
                            "responses": {
                                "poison": poison_response.text[:200],
                                "verify": verify_response.text[:200]
                            }
                        }
                    })
                    
            except requests.exceptions.RequestException:
                continue
                
    except Exception as e:
        print(f"Error in cache poisoning check: {str(e)}")
    
    return findings

def is_cache_poisoned(poison_response: requests.Response, verify_response: requests.Response, test: Dict) -> bool:
    # Check for cache poisoning indicators
    
    # Check cache-related headers
    cache_headers = [
        'x-cache',
        'x-cache-hits',
        'cf-cache-status',
        'age',
        'cache-control'
    ]
    
    # Look for cache hits in verification response
    if any(h in verify_response.headers.keys() for h in cache_headers):
        # Check if poisoned content is reflected
        if any(v in verify_response.text for v in test['headers'].values()):
            return True
    
    # Check for inconsistent caching behavior
    if 'cache-control' in poison_response.headers:
        if 'public' in poison_response.headers['cache-control'].lower():
            if poison_response.text == verify_response.text:
                return True
    
    # Check for reflected cache headers
    for header in test['headers'].keys():
        if header.lower() in verify_response.headers:
            return True
    
    # Check for cached error responses
    if verify_response.status_code in [200, 304] and poison_response.status_code >= 400:
        return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_cache_poisoning(
            "http://localhost:5000",
            "/api/data",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())