#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin, parse_qs, urlparse
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_open_redirect(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        parsed_url = urlparse(test_url)
        query_params = parse_qs(parsed_url.query)
        
        # Open redirect test payloads
        payloads = [
            {
                'payload': 'https://evil.com',
                'desc': 'Basic redirect'
            },
            {
                'payload': '//evil.com',
                'desc': 'Protocol-relative URL'
            },
            {
                'payload': 'https:evil.com',
                'desc': 'Malformed URL'
            },
            {
                'payload': 'javascript:alert(document.domain)',
                'desc': 'JavaScript protocol'
            },
            {
                'payload': 'data:text/html,<script>window.location="https://evil.com"</script>',
                'desc': 'Data URL'
            }
        ]
        
        # Redirect-related parameters to test
        redirect_params = ['redirect', 'url', 'next', 'target', 'redir', 'destination', 'return', 'returnTo', 'goto', 'link']
        
        # Test query parameters
        for param_name, param_value in query_params.items():
            if any(rp in param_name.lower() for rp in redirect_params):
                for test in payloads:
                    modified_params = query_params.copy()
                    modified_params[param_name] = [test['payload']]
                    
                    try:
                        response = requests.request(
                            method,
                            test_url,
                            params=modified_params,
                            headers={'Content-Type': 'application/json'},
                            timeout=5,
                            allow_redirects=False
                        )
                        
                        if is_open_redirect_vulnerable(response, test['payload']):
                            findings.append({
                                "type": "Open Redirect",
                                "detail": f"{test['desc']} in parameter {param_name}",
                                "evidence": {
                                    "url": test_url,
                                    "parameter": param_name,
                                    "payload": test['payload'],
                                    "status_code": response.status_code,
                                    "location": response.headers.get('location', ''),
                                    "response": response.text[:200]
                                }
                            })
                    except requests.exceptions.RequestException:
                        continue
        
        # Test request body
        if method in ['POST', 'PUT']:
            for test in payloads:
                try:
                    response = requests.request(
                        method,
                        test_url,
                        json={"redirect_url": test['payload']},
                        headers={'Content-Type': 'application/json'},
                        timeout=5,
                        allow_redirects=False
                    )
                    
                    if is_open_redirect_vulnerable(response, test['payload']):
                        findings.append({
                            "type": "Open Redirect",
                            "detail": f"{test['desc']} in request body",
                            "evidence": {
                                "url": test_url,
                                "payload": test['payload'],
                                "status_code": response.status_code,
                                "location": response.headers.get('location', ''),
                                "response": response.text[:200]
                            }
                        })
                except requests.exceptions.RequestException:
                    continue
                
    except Exception as e:
        print(f"Error in open redirect check: {str(e)}")
    
    return findings

def is_open_redirect_vulnerable(response: requests.Response, payload: str) -> bool:
    # Check for open redirect indicators
    
    # Check redirect status codes
    if response.status_code in [301, 302, 303, 307, 308]:
        location = response.headers.get('location', '').lower()
        payload_lower = payload.lower()
        
        # Check if payload is in location header
        if payload_lower in location:
            return True
        
        # Check for partial matches (domain)
        if 'evil.com' in location:
            return True
        
        # Check for JavaScript protocol
        if 'javascript:' in location:
            return True
        
        # Check for data URL
        if 'data:' in location:
            return True
    
    # Check for meta refresh tags
    response_text = response.text.lower()
    if '<meta http-equiv="refresh"' in response_text:
        if payload.lower() in response_text:
            return True
    
    # Check for JavaScript redirects
    js_redirects = [
        'window.location',
        'document.location',
        'window.navigate',
        'window.open',
        'self.location'
    ]
    
    if any(jr in response_text for jr in js_redirects):
        if payload.lower() in response_text:
            return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_open_redirect(
            "http://localhost:5000",
            "/api/redirect?url=https://example.com",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())