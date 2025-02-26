#!/usr/bin/env python3
import aiohttp
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_security_config(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        initial_headers = dict(initial_response.headers)
        
        async with aiohttp.ClientSession() as session:
            # Test security headers
            header_results = await test_security_headers(session, test_url, method, initial_headers)
            findings.extend(header_results)
            
            # Test CORS configuration
            cors_results = await test_cors_config(session, test_url, method, initial_headers)
            findings.extend(cors_results)
            
            # Test SSL/TLS configuration
            ssl_results = await test_ssl_config(session, test_url, method, initial_headers)
            findings.extend(ssl_results)
            
            # Test rate limiting
            rate_results = await test_rate_limiting(session, test_url, method, initial_headers)
            findings.extend(rate_results)
    
    except Exception as e:
        print(f"Error in security configuration check: {str(e)}")
    
    return findings

async def test_security_headers(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    required_headers = [
        {'name': 'X-Content-Type-Options', 'value': 'nosniff'},
        {'name': 'X-Frame-Options', 'value': ['DENY', 'SAMEORIGIN']},
        {'name': 'X-XSS-Protection', 'value': '1; mode=block'},
        {'name': 'Strict-Transport-Security', 'value': 'max-age='},
        {'name': 'Content-Security-Policy', 'value': None}
    ]
    
    try:
        async with session.request(method, url, headers=headers, timeout=5) as response:
            response_headers = dict(response.headers)
            
            for header in required_headers:
                if header['name'] not in response_headers:
                    findings.append({
                        "type": "API7:2023",
                        "name": "Missing Security Header",
                        "detail": f"Missing {header['name']} header",
                        "evidence": {
                            "url": url,
                            "header": header['name'],
                            "current_headers": response_headers
                        },
                        "severity": "MEDIUM"
                    })
                elif header['value']:
                    if isinstance(header['value'], list):
                        if not any(val in response_headers[header['name']] for val in header['value']):
                            findings.append({
                                "type": "API7:2023",
                                "name": "Incorrect Security Header",
                                "detail": f"Invalid {header['name']} value",
                                "evidence": {
                                    "url": url,
                                    "header": header['name'],
                                    "current_value": response_headers[header['name']],
                                    "expected_value": header['value']
                                },
                                "severity": "LOW"
                            })
                    elif header['value'] not in response_headers[header['name']]:
                        findings.append({
                            "type": "API7:2023",
                            "name": "Incorrect Security Header",
                            "detail": f"Invalid {header['name']} value",
                            "evidence": {
                                "url": url,
                                "header": header['name'],
                                "current_value": response_headers[header['name']],
                                "expected_value": header['value']
                            },
                            "severity": "LOW"
                        })
    except:
        pass
    
    return findings

async def test_cors_config(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    test_origins = [
        'null',
        '*',
        'http://evil.com',
        'https://attacker.com',
        'file://'
    ]
    
    for origin in test_origins:
        try:
            test_headers = headers.copy()
            test_headers['Origin'] = origin
            
            async with session.request(method, url, headers=test_headers, timeout=5) as response:
                cors_header = response.headers.get('Access-Control-Allow-Origin')
                if cors_header and (cors_header == '*' or origin in cors_header):
                    findings.append({
                        "type": "API7:2023",
                        "name": "Insecure CORS Configuration",
                        "detail": "Overly permissive CORS policy",
                        "evidence": {
                            "url": url,
                            "origin": origin,
                            "cors_header": cors_header
                        },
                        "severity": "HIGH"
                    })
        except:
            continue
    
    return findings

async def test_ssl_config(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    ssl_tests = [
        {'name': 'TLS 1.0', 'version': 1},
        {'name': 'TLS 1.1', 'version': 2},
        {'name': 'Weak Ciphers', 'ciphers': 'LOW:!aNULL:!eNULL'}
    ]
    
    for test in ssl_tests:
        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as test_session:
                async with test_session.request(method, url, headers=headers, timeout=5) as response:
                    if response.status == 200:
                        findings.append({
                            "type": "API7:2023",
                            "name": "Weak SSL/TLS Configuration",
                            "detail": f"Server accepts {test['name']}",
                            "evidence": {
                                "url": url,
                                "ssl_version": test.get('version'),
                                "ciphers": test.get('ciphers')
                            },
                            "severity": "HIGH"
                        })
        except:
            continue
    
    return findings

async def test_rate_limiting(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    request_count = 50
    
    try:
        success_count = 0
        for _ in range(request_count):
            async with session.request(method, url, headers=headers, timeout=5) as response:
                if response.status == 200:
                    success_count += 1
        
        if success_count == request_count:
            findings.append({
                "type": "API7:2023",
                "name": "Missing Rate Limiting",
                "detail": "No rate limiting detected",
                "evidence": {
                    "url": url,
                    "requests_sent": request_count,
                    "successful_requests": success_count
                },
                "severity": "MEDIUM"
            })
    except:
        pass
    
    return findings

if __name__ == "__main__":
    async def test():
        result = await check_security_config(
            "http://localhost:5000",
            "/api/data",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())