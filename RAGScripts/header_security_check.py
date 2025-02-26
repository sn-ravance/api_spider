#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_header_security(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        initial_headers = dict(initial_response.headers)
        
        async with aiohttp.ClientSession() as session:
            # Security header checks
            security_headers = {
                'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
                'X-Content-Type-Options': ['nosniff'],
                'X-XSS-Protection': ['1', '1; mode=block'],
                'Strict-Transport-Security': ['max-age='],
                'Content-Security-Policy': ['default-src', 'script-src', 'frame-ancestors'],
                'Referrer-Policy': ['strict-origin', 'strict-origin-when-cross-origin', 'same-origin'],
                'Permissions-Policy': ['geolocation', 'microphone', 'camera'],
                'Cache-Control': ['no-store', 'no-cache', 'private'],
                'Clear-Site-Data': ['cache', 'cookies', 'storage'],
                'Cross-Origin-Embedder-Policy': ['require-corp'],
                'Cross-Origin-Opener-Policy': ['same-origin'],
                'Cross-Origin-Resource-Policy': ['same-origin']
            }
            
            # Check for missing security headers
            async with session.request(method, test_url, headers=initial_headers) as response:
                headers = response.headers
                
                for header, expected_values in security_headers.items():
                    if header not in headers:
                        findings.append({
                            "type": "API7:2023",
                            "name": "Security Misconfiguration",
                            "detail": f"Missing {header} header",
                            "evidence": {
                                "url": test_url,
                                "header": header,
                                "expected": expected_values,
                                "found": None
                            },
                            "severity": "MEDIUM"
                        })
                    else:
                        header_value = headers[header].lower()
                        if not any(value.lower() in header_value for value in expected_values):
                            findings.append({
                                "type": "API7:2023",
                                "name": "Security Misconfiguration",
                                "detail": f"Potentially weak {header} configuration",
                                "evidence": {
                                    "url": test_url,
                                    "header": header,
                                    "expected": expected_values,
                                    "found": headers[header]
                                },
                                "severity": "LOW"
                            })
            
            # Test header injection vulnerabilities
            injection_results = await test_header_injection(session, test_url, method, initial_headers)
            findings.extend(injection_results)
            
    except Exception as e:
        print(f"Error in header security check: {str(e)}")
    
    return findings

async def test_header_injection(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    test_cases = [
        {
            'name': 'Header Injection',
            'headers': {
                'X-Forwarded-For': ['127.0.0.1', '0:0:0:0:0:0:0:1'],
                'X-Forwarded-Host': ['evil.com', '127.0.0.1:80'],
                'X-Original-URL': ['/admin', '/private'],
                'X-Rewrite-URL': ['/admin', '/private'],
                'X-Custom-IP-Authorization': ['127.0.0.1']
            }
        },
        {
            'name': 'Cache Poisoning',
            'headers': {
                'X-Host': ['evil.com'],
                'X-Forwarded-Server': ['evil.com'],
                'X-HTTP-Host-Override': ['evil.com'],
                'Forwarded': ['for=127.0.0.1;host=evil.com'],
                'X-Forwarded-Proto': ['http']
            }
        }
    ]
    
    for test in test_cases:
        for header_name, values in test['headers'].items():
            for value in values:
                try:
                    test_headers = headers.copy()
                    test_headers[header_name] = value
                    
                    async with session.request(method, url, headers=test_headers, allow_redirects=False) as response:
                        if await is_header_vulnerable(response, test, header_name, value):
                            findings.append({
                                "type": "API7:2023",
                                "name": "Security Misconfiguration",
                                "detail": f"Potential {test['name']} vulnerability",
                                "evidence": {
                                    "url": url,
                                    "header": header_name,
                                    "value": value,
                                    "status_code": response.status,
                                    "response_headers": dict(response.headers)
                                },
                                "severity": "HIGH"
                            })
                except:
                    continue
    
    return findings

async def is_header_vulnerable(response: aiohttp.ClientResponse, test: Dict, header_name: str, value: str) -> bool:
    try:
        if test['name'] == 'Header Injection':
            if response.status in [200, 301, 302]:
                if any(h.lower() == header_name.lower() for h in response.headers):
                    return True
                if 'location' in response.headers:
                    if value.lower() in response.headers['location'].lower():
                        return True
        
        if test['name'] == 'Cache Poisoning':
            cache_headers = ['x-cache', 'cf-cache-status', 'age', 'cache-control']
            if any(h.lower() in response.headers for h in cache_headers):
                if response.status == 200:
                    return True
        
        response_headers = str(response.headers).lower()
        if value.lower() in response_headers:
            return True
        
    except:
        pass
    
    return False

if __name__ == "__main__":
    async def test():
        result = await check_header_security(
            "http://localhost:5000",
            "/",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())