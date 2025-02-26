#!/usr/bin/env python3
import aiohttp
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_mass_assignment(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        initial_headers = dict(initial_response.headers)
        
        async with aiohttp.ClientSession() as session:
            # Test sensitive field overwrite
            sensitive_results = await test_sensitive_fields(session, test_url, method, initial_headers)
            findings.extend(sensitive_results)
            
            # Test parameter pollution
            pollution_results = await test_parameter_pollution(session, test_url, method, initial_headers)
            findings.extend(pollution_results)
            
            # Test nested objects
            nested_results = await test_nested_objects(session, test_url, method, initial_headers)
            findings.extend(nested_results)
            
            # Test array manipulation
            array_results = await test_array_manipulation(session, test_url, method, initial_headers)
            findings.extend(array_results)
    
    except Exception as e:
        print(f"Error in mass assignment check: {str(e)}")
    
    return findings

async def test_sensitive_fields(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    sensitive_fields = [
        {'field': 'role', 'value': 'admin'},
        {'field': 'isAdmin', 'value': True},
        {'field': 'permissions', 'value': ['admin', 'superuser']},
        {'field': 'accessLevel', 'value': 9999},
        {'field': 'verified', 'value': True}
    ]
    
    for field in sensitive_fields:
        try:
            payload = {field['field']: field['value']}
            async with session.request(method, url, json=payload, headers=headers, timeout=5) as response:
                if response.status == 200:
                    findings.append({
                        "type": "API6:2023",
                        "name": "Mass Assignment",
                        "detail": f"Sensitive field {field['field']} can be overwritten",
                        "evidence": {
                            "url": url,
                            "field": field['field'],
                            "value": field['value'],
                            "response_code": response.status
                        },
                        "severity": "HIGH"
                    })
        except:
            continue
    
    return findings

async def test_parameter_pollution(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    pollution_tests = [
        {'name': 'id', 'values': ['1', '2']},
        {'name': 'user_id', 'values': ['1', '2']},
        {'name': 'email', 'values': ['test1@example.com', 'test2@example.com']},
        {'name': 'status', 'values': ['active', 'disabled']}
    ]
    
    for test in pollution_tests:
        try:
            params = {test['name']: test['values']}
            async with session.request(method, url, params=params, headers=headers, timeout=5) as response:
                if response.status == 200:
                    findings.append({
                        "type": "API6:2023",
                        "name": "Parameter Pollution",
                        "detail": f"Multiple values accepted for {test['name']}",
                        "evidence": {
                            "url": url,
                            "parameter": test['name'],
                            "values": test['values'],
                            "response_code": response.status
                        },
                        "severity": "MEDIUM"
                    })
        except:
            continue
    
    return findings

async def test_nested_objects(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    nested_payloads = [
        {
            'user': {
                'profile': {
                    'role': 'admin'
                }
            }
        },
        {
            'settings': {
                'security': {
                    'enabled': False
                }
            }
        },
        {
            'account': {
                'permissions': {
                    'all': True
                }
            }
        }
    ]
    
    for payload in nested_payloads:
        try:
            async with session.request(method, url, json=payload, headers=headers, timeout=5) as response:
                if response.status == 200:
                    findings.append({
                        "type": "API6:2023",
                        "name": "Nested Object Assignment",
                        "detail": "Nested object modification accepted",
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

async def test_array_manipulation(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    array_tests = [
        {'roles': ['user', 'admin']},
        {'groups': ['users', 'administrators']},
        {'permissions': ['read', 'write', 'execute']},
        {'access': ['full', 'unrestricted']}
    ]
    
    for test in array_tests:
        try:
            async with session.request(method, url, json=test, headers=headers, timeout=5) as response:
                if response.status == 200:
                    findings.append({
                        "type": "API6:2023",
                        "name": "Array Manipulation",
                        "detail": "Array modification accepted",
                        "evidence": {
                            "url": url,
                            "payload": test,
                            "response_code": response.status
                        },
                        "severity": "MEDIUM"
                    })
        except:
            continue
    
    return findings

if __name__ == "__main__":
    async def test():
        result = await check_mass_assignment(
            "http://localhost:5000",
            "/api/users",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())