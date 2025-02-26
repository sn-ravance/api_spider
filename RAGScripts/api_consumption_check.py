#!/usr/bin/env python3
import aiohttp
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
import re
from RAGScripts.utils.logger import setup_scanner_logger

async def check_api_consumption(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        initial_headers = dict(initial_response.headers)
        
        async with aiohttp.ClientSession() as session:
            # Test content type validation
            content_results = await test_content_validation(session, test_url, method, initial_headers)
            findings.extend(content_results)
            
            # Test response parsing
            parse_results = await test_response_parsing(session, test_url, method, initial_headers)
            findings.extend(parse_results)
            
            # Test client-side validation
            validation_results = await test_client_validation(session, test_url, method, initial_headers)
            findings.extend(validation_results)
            
            # Test error handling
            error_results = await test_error_handling(session, test_url, method, initial_headers)
            findings.extend(error_results)
    
    except Exception as e:
        print(f"Error in API consumption check: {str(e)}")
    
    return findings

async def test_content_validation(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    content_tests = [
        {'Content-Type': 'application/xml', 'data': '<test>data</test>'},
        {'Content-Type': 'text/html', 'data': '<html><body>test</body></html>'},
        {'Content-Type': 'text/plain', 'data': 'test data'},
        {'Content-Type': 'application/octet-stream', 'data': b'binary data'}
    ]
    
    for test in content_tests:
        try:
            test_headers = headers.copy()
            test_headers.update({'Content-Type': test['Content-Type']})
            
            async with session.request(method, url, data=test['data'], headers=test_headers, timeout=5) as response:
                if response.status == 200:
                    findings.append({
                        "type": "API10:2023",
                        "name": "Unsafe Content Handling",
                        "detail": f"Server accepts {test['Content-Type']} without validation",
                        "evidence": {
                            "url": url,
                            "content_type": test['Content-Type'],
                            "response_code": response.status
                        },
                        "severity": "MEDIUM"
                    })
        except:
            continue
    
    return findings

async def test_response_parsing(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    malformed_responses = [
        '{"invalid": json',
        '<xml>invalid<xml>',
        'null',
        '[1,2,3'
    ]
    
    for response_data in malformed_responses:
        try:
            test_headers = headers.copy()
            test_headers['X-Test-Response'] = 'malformed'
            
            async with session.request(method, url, headers=test_headers, data=response_data, timeout=5) as response:
                response_text = await response.text()
                if not await is_valid_response(response_text):
                    findings.append({
                        "type": "API10:2023",
                        "name": "Unsafe Response Parsing",
                        "detail": "Server returns malformed response",
                        "evidence": {
                            "url": url,
                            "response_snippet": response_text[:200],
                            "response_code": response.status
                        },
                        "severity": "HIGH"
                    })
        except:
            continue
    
    return findings

async def test_client_validation(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    validation_tests = [
        {'field': 'email', 'value': 'invalid-email'},
        {'field': 'date', 'value': '2023-13-45'},
        {'field': 'phone', 'value': '+1234invalid'},
        {'field': 'url', 'value': 'not-a-url'}
    ]
    
    for test in validation_tests:
        try:
            payload = {test['field']: test['value']}
            async with session.request(method, url, json=payload, headers=headers, timeout=5) as response:
                if response.status == 200:
                    findings.append({
                        "type": "API10:2023",
                        "name": "Missing Client Validation",
                        "detail": f"Server accepts invalid {test['field']} format",
                        "evidence": {
                            "url": url,
                            "field": test['field'],
                            "invalid_value": test['value'],
                            "response_code": response.status
                        },
                        "severity": "LOW"
                    })
        except:
            continue
    
    return findings

async def test_error_handling(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    error_tests = [
        {'status': 400, 'message': 'Bad Request'},
        {'status': 401, 'message': 'Unauthorized'},
        {'status': 403, 'message': 'Forbidden'},
        {'status': 404, 'message': 'Not Found'},
        {'status': 500, 'message': 'Internal Server Error'}
    ]
    
    for test in error_tests:
        try:
            test_headers = headers.copy()
            test_headers['X-Test-Error'] = str(test['status'])
            
            async with session.request(method, url, headers=test_headers, timeout=5) as response:
                if response.status == test['status']:
                    response_text = await response.text()
                    if await contains_sensitive_error(response_text):
                        findings.append({
                            "type": "API10:2023",
                            "name": "Unsafe Error Handling",
                            "detail": f"Sensitive information in {test['status']} error",
                            "evidence": {
                                "url": url,
                                "error_code": test['status'],
                                "response_snippet": response_text[:200]
                            },
                            "severity": "HIGH"
                        })
        except:
            continue
    
    return findings

async def is_valid_response(response_text: str) -> bool:
    try:
        if response_text.startswith('{') or response_text.startswith('['):
            json.loads(response_text)
        elif response_text.startswith('<'):
            return bool(re.match(r'^<\?xml|^<[a-zA-Z]', response_text))
        return True
    except:
        return False

async def contains_sensitive_error(response_text: str) -> bool:
    sensitive_patterns = [
        r'stack trace',
        r'exception in',
        r'error in',
        r'failed to',
        r'database error',
        r'syntax error',
        r'internal error'
    ]
    
    return any(re.search(pattern, response_text, re.IGNORECASE) for pattern in sensitive_patterns)

if __name__ == "__main__":
    async def test():
        result = await check_api_consumption(
            "http://localhost:5000",
            "/api/data",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())