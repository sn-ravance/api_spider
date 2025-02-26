#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_graphql_variables(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for GraphQL variable abuse
        test_cases = [
            {
                'name': 'Variable injection',
                'query': '''
                    query ($id: ID!, $filter: String!) {
                        user(id: $id) {
                            data(filter: $filter)
                        }
                    }
                ''',
                'variables': {
                    'id': '1; DROP TABLE users;',
                    'filter': '{"$where": "this.admin === true"}'
                }
            },
            {
                'name': 'Variable type coercion',
                'query': '''
                    mutation ($input: UserInput!) {
                        updateUser(input: $input) {
                            success
                        }
                    }
                ''',
                'variables': {
                    'input': {
                        'id': '1',
                        'role': 1337,
                        'isAdmin': 'true',
                        'permissions': ['ADMIN', 'SYSTEM']
                    }
                }
            },
            {
                'name': 'Nested variable manipulation',
                'query': '''
                    query ($complex: ComplexInput!) {
                        processData(input: $complex) {
                            result
                        }
                    }
                ''',
                'variables': {
                    'complex': {
                        '__proto__': {'admin': true},
                        'constructor': {'prototype': {'elevated': true}},
                        'data': {'$ne': null}
                    }
                }
            },
            {
                'name': 'Variable default bypass',
                'query': '''
                    query ($level: String = "USER", $access: Boolean = false) {
                        secureData(level: $level, override: $access) {
                            sensitiveInfo
                            internalData
                        }
                    }
                ''',
                'variables': {
                    'level': 'ADMIN',
                    'access': true
                }
            }
        ]
        
        for test in test_cases:
            try:
                response = requests.post(
                    test_url,
                    json={
                        'query': test['query'],
                        'variables': test['variables']
                    },
                    headers={'Content-Type': 'application/json'},
                    timeout=5
                )
                
                if is_variable_vulnerable(response, test):
                    findings.append({
                        "type": "GraphQL Variable Abuse",
                        "detail": f"Potential {test['name']} vulnerability",
                        "evidence": {
                            "url": test_url,
                            "query": test['query'],
                            "variables": test['variables'],
                            "status_code": response.status_code,
                            "response": response.text[:200]
                        }
                    })
                    
            except requests.exceptions.RequestException:
                continue
                
    except Exception as e:
        print(f"Error in GraphQL variable check: {str(e)}")
    
    return findings

def is_variable_vulnerable(response: requests.Response, test: Dict) -> bool:
    try:
        response_json = response.json()
    except json.JSONDecodeError:
        return False
    
    response_text = json.dumps(response_json).lower()
    
    # Check for variable injection
    if test['name'] == 'Variable injection':
        if response.status_code == 200:
            if 'data' in response_text and not response_json.get('errors'):
                return True
    
    # Check for type coercion success
    if test['name'] == 'Variable type coercion':
        if response.status_code == 200:
            if 'success' in response_text and not response_json.get('errors'):
                return True
    
    # Check for nested manipulation
    if test['name'] == 'Nested variable manipulation':
        if response.status_code == 200:
            if 'result' in response_text and not response_json.get('errors'):
                return True
    
    # Check for default value bypass
    if test['name'] == 'Variable default bypass':
        if 'sensitiveinfo' in response_text or 'internaldata' in response_text:
            return True
    
    # Check for error messages indicating variable issues
    error_indicators = [
        'variable',
        'invalid type',
        'coercion failed',
        'validation error',
        'malformed input'
    ]
    
    if any(indicator in response_text for indicator in error_indicators):
        if response.status_code < 400:
            return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_graphql_variables(
            "http://localhost:5000",
            "/graphql",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())