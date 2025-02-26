#!/usr/bin/env python3
import aiohttp
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
import re
from RAGScripts.utils.logger import setup_scanner_logger

async def check_security_misconfig(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
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
            
            # Test debug endpoints
            debug_results = await test_debug_endpoints(session, test_url, method, initial_headers)
            findings.extend(debug_results)
            
            # Test default configurations
            default_results = await test_default_configs(session, test_url, method, initial_headers)
            findings.extend(default_results)
    
    except Exception as e:
        print(f"Error in security misconfiguration check: {str(e)}")
    
    return findings

async def test_security_headers(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    required_headers = {
        'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
        'X-Content-Type-Options': ['nosniff'],
        'X-XSS-Protection': ['1; mode=block'],
        'Strict-Transport-Security': ['max-age='],
        'Content-Security-Policy': ['default-src', 'script-src'],
        'Referrer-Policy': ['strict-origin', 'no-referrer']
    }
    
    try:
        async with session.request(method, url, headers=headers, timeout=5) as response:
            response_headers = dict(response.headers)
            
            for header, expected_values in required_headers.items():
                if header not in response_headers:
                    findings.append({
                        "type": "API7:2023",
                        "name": "Security Misconfiguration",
                        "detail": f"Missing security header: {header}",
                        "evidence": {
                            "url": url,
                            "missing_header": header,
                            "current_headers": list(response_headers.keys())
                        },
                        "severity": "MEDIUM"
                    })
                else:
                    if not any(ev.lower() in response_headers[header].lower() for ev in expected_values):
                        findings.append({
                            "type": "API7:2023",
                            "name": "Security Misconfiguration",
                            "detail": f"Incorrect security header value: {header}",
                            "evidence": {
                                "url": url,
                                "header": header,
                                "current_value": response_headers[header],
                                "expected_values": expected_values
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
                cors_headers = {
                    'Access-Control-Allow-Origin': origin,
                    'Access-Control-Allow-Credentials': 'true'
                }
                
                response_headers = dict(response.headers)
                
                if any(ch in response_headers and response_headers[ch] == cv 
                      for ch, cv in cors_headers.items()):
                    findings.append({
                        "type": "API7:2023",
                        "name": "Security Misconfiguration",
                        "detail": "Insecure CORS configuration",
                        "evidence": {
                            "url": url,
                            "origin": origin,
                            "cors_headers": {k: response_headers.get(k) for k in cors_headers}
                        },
                        "severity": "HIGH"
                    })
        except:
            continue
    
    return findings

async def test_debug_endpoints(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    debug_paths = [
        '/debug',
        '/actuator',
        '/metrics',
        '/trace',
        '/env',
        '/management',
        '/console',
        '/.git',
        '/.env',
        '/swagger-ui.html'
    ]
    
    base_url = '/'.join(url.split('/')[:3])  # Get base URL
    
    for path in debug_paths:
        try:
            test_url = urljoin(base_url, path)
            async with session.request('GET', test_url, headers=headers, timeout=5) as response:
                if response.status != 404:
                    findings.append({
                        "type": "API7:2023",
                        "name": "Security Misconfiguration",
                        "detail": "Exposed debug/management endpoint",
                        "evidence": {
                            "url": test_url,
                            "status_code": response.status,
                            "response_length": len(await response.text())
                        },
                        "severity": "CRITICAL"
                    })
        except:
            continue
    
    return findings

async def test_default_configs(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    default_checks = [
        {
            'path': '/admin',
            'credentials': {'username': 'admin', 'password': 'admin'}
        },
        {
            'path': '/login',
            'credentials': {'username': 'root', 'password': 'root'}
        },
        {
            'path': '/manager',
            'credentials': {'username': 'tomcat', 'password': 'tomcat'}
        }
    ]
    
    base_url = '/'.join(url.split('/')[:3])
    
    for check in default_checks:
        try:
            test_url = urljoin(base_url, check['path'])
            async with session.request('POST', test_url, json=check['credentials'], headers=headers, timeout=5) as response:
                if response.status == 200:
                    findings.append({
                        "type": "API7:2023",
                        "name": "Security Misconfiguration",
                        "detail": "Default credentials accepted",
                        "evidence": {
                            "url": test_url,
                            "credentials": check['credentials'],
                            "response_code": response.status
                        },
                        "severity": "CRITICAL"
                    })
        except:
            continue
    
    return findings

if __name__ == "__main__":
    async def test():
        result = await check_security_misconfig(
            "http://localhost:5000",
            "/api/data",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())