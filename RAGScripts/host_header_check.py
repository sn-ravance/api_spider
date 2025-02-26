#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_host_header(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        parsed_host = urlparse(test_url).netloc
        
        # Host header test cases
        test_cases = [
            {
                'name': 'Host override',
                'headers': {'Host': 'evil.com'}
            },
            {
                'name': 'Multiple Host headers',
                'headers': {'Host': [parsed_host, 'evil.com']}
            },
            {
                'name': 'X-Forwarded-Host injection',
                'headers': {
                    'Host': parsed_host,
                    'X-Forwarded-Host': 'evil.com'
                }
            },
            {
                'name': 'Line injection in Host',
                'headers': {'Host': f'{parsed_host}\r\nSet-Cookie: session=hacked'}
            },
            {
                'name': 'Malformed port in Host',
                'headers': {'Host': f'{parsed_host}:443:80'}
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
                
                if is_host_header_vulnerable(response, base_response, test):
                    findings.append({
                        "type": "Host Header Injection",
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
        print(f"Error in host header check: {str(e)}")
    
    return findings

def is_host_header_vulnerable(response: requests.Response, base_response: requests.Response, test: Dict) -> bool:
    # Check for host header injection indicators
    
    # Check for reflected host values
    injected_hosts = []
    for header_value in test['headers'].values():
        if isinstance(header_value, list):
            injected_hosts.extend(header_value)
        else:
            injected_hosts.append(header_value)
    
    response_text = response.text.lower()
    for host in injected_hosts:
        if isinstance(host, str) and host.lower() in response_text:
            return True
    
    # Check for new or modified cookies
    base_cookies = base_response.headers.get('set-cookie', '')
    response_cookies = response.headers.get('set-cookie', '')
    if response_cookies != base_cookies:
        return True
    
    # Check for unusual redirects
    if response.status_code in [301, 302, 307, 308]:
        location = response.headers.get('location', '').lower()
        if any(host.lower() in location for host in injected_hosts if isinstance(host, str)):
            return True
    
    # Check for error messages indicating host header processing
    error_indicators = [
        'invalid host',
        'host not allowed',
        'bad host header',
        'unknown host',
        'host validation'
    ]
    
    if any(indicator in response_text for indicator in error_indicators):
        return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    from urllib.parse import urlparse
    
    async def test():
        result = await check_host_header(
            "http://localhost:5000",
            "/api/test",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())