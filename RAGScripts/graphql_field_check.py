#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_graphql_fields(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for GraphQL field suggestion abuse
        test_cases = [
            {
                'name': 'Field suggestion bypass',
                'query': '''
                    query {
                        user(id: 1) {
                            __typename
                            __type
                            _internal_id
                            _secret_key
                        }
                    }
                '''
            },
            {
                'name': 'Hidden field exposure',
                'query': '''
                    query {
                        user(id: 1) {
                            password
                            hashedPassword
                            salt
                            secretToken
                            apiKey
                        }
                    }
                '''
            },
            {
                'name': 'Debug field access',
                'query': '''
                    query {
                        user(id: 1) {
                            debug_info
                            trace_data
                            error_log
                            system_info
                        }
                    }
                '''
            },
            {
                'name': 'Internal field enumeration',
                'query': '''
                    query {
                        __type(name: "User") {
                            fields {
                                name
                                isDeprecated
                                description
                            }
                        }
                    }
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
                
                if is_field_vulnerable(response, test):
                    findings.append({
                        "type": "GraphQL Field Suggestion",
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
        print(f"Error in GraphQL field check: {str(e)}")
    
    return findings

def is_field_vulnerable(response: Response, test: Dict) -> bool:
    try:
        response_json = response.json()
    except json.JSONDecodeError:
        return False
    
    response_text = json.dumps(response_json).lower()
    
    # Check for internal field exposure
    if test['name'] == 'Field suggestion bypass':
        internal_fields = ['__type', '_internal', '_secret']
        if any(field in response_text for field in internal_fields):
            return True
    
    # Check for sensitive field exposure
    if test['name'] == 'Hidden field exposure':
        sensitive_fields = ['password', 'hash', 'salt', 'token', 'key']
        if any(field in response_text for field in sensitive_fields):
            return True
    
    # Check for debug information exposure
    if test['name'] == 'Debug field access':
        debug_fields = ['debug', 'trace', 'error_log', 'system_info']
        if any(field in response_text for field in debug_fields):
            return True
    
    # Check for internal field enumeration
    if test['name'] == 'Internal field enumeration':
        if response.status_code == 200 and '__type' in response_text:
            if 'fields' in response_text and len(response_json.get('data', {}).get('__type', {}).get('fields', [])) > 0:
                return True
    
    # Check for error messages indicating field issues
    error_indicators = [
        'unknown field',
        'field not found',
        'cannot query field',
        'field does not exist',
        'undefined field'
    ]
    
    if any(indicator in response_text for indicator in error_indicators):
        if response.status_code < 400:
            return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_graphql_fields(
            "http://localhost:5000",
            "/graphql",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())