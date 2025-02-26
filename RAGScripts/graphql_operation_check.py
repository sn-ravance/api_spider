#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_graphql_operations(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for GraphQL operation name abuse
        test_cases = [
            {
                'name': 'Operation name injection',
                'query': '''
                    query malicious_operation_1337' { # OR 1=1
                        user(id: 1) {
                            name
                            email
                        }
                    }
                '''
            },
            {
                'name': 'Multiple operation definitions',
                'query': '''
                    query op1 { user(id: 1) { name } }
                    query op2 { user(id: 2) { name } }
                    query op3 { user(id: 3) { name } }
                    query op4 { user(id: 4) { name } }
                '''
            },
            {
                'name': 'Anonymous operation mixing',
                'query': '''
                    query { user(id: 1) { name } }
                    mutation { updateUser(id: 1) { success } }
                    subscription { userUpdates { id } }
                '''
            },
            {
                'name': 'Operation name conflicts',
                'query': '''
                    query getUserData { user(id: 1) { name } }
                    query getUserData { user(id: 2) { email } }
                '''
            }
        ]
        
        for test in test_cases:
            try:
                response = requests.post(
                    test_url,
                    json={'query': test['query']},
                    headers={'Content-Type': 'application/json'},
                    timeout=5
                )
                
                if is_operation_vulnerable(response, test):
                    findings.append({
                        "type": "GraphQL Operation Abuse",
                        "detail": f"Potential {test['name']} vulnerability",
                        "evidence": {
                            "url": test_url,
                            "query": test['query'],
                            "status_code": response.status_code,
                            "response": response.text[:200]
                        }
                    })
                    
            except requests.exceptions.RequestException:
                continue
                
    except Exception as e:
        print(f"Error in GraphQL operation check: {str(e)}")
    
    return findings

def is_operation_vulnerable(response: requests.Response, test: Dict) -> bool:
    try:
        response_json = response.json()
    except json.JSONDecodeError:
        return False
    
    response_text = json.dumps(response_json).lower()
    
    # Check for operation name injection
    if test['name'] == 'Operation name injection':
        if response.status_code == 200 and 'data' in response_json:
            if 'error' not in response_json:
                return True
    
    # Check for multiple operation acceptance
    if test['name'] == 'Multiple operation definitions':
        if response.status_code == 200:
            operation_count = len([k for k in response_json.get('data', {}) if k])
            if operation_count > 1:
                return True
    
    # Check for mixed operation types
    if test['name'] == 'Anonymous operation mixing':
        if response.status_code == 200:
            if 'data' in response_json and not response_json.get('errors'):
                return True
    
    # Check for operation name conflicts
    if test['name'] == 'Operation name conflicts':
        if response.status_code == 200:
            if 'data' in response_json and not response_json.get('errors'):
                return True
    
    # Check for error messages indicating operation issues
    error_indicators = [
        'operation not found',
        'multiple operations',
        'operation name',
        'anonymous operations',
        'operation conflict'
    ]
    
    if any(indicator in response_text for indicator in error_indicators):
        if response.status_code < 400:
            return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_graphql_operations(
            "http://localhost:5000",
            "/graphql",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())