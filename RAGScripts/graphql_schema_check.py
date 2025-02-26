#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_graphql_schema(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for GraphQL schema abuse
        test_cases = [
            {
                'name': 'Schema introspection',
                'query': '''
                    query {
                        __schema {
                            types {
                                name
                                fields {
                                    name
                                    type {
                                        name
                                    }
                                }
                            }
                        }
                    }
                '''
            },
            {
                'name': 'Type introspection',
                'query': '''
                    query {
                        __type(name: "User") {
                            name
                            fields {
                                name
                                type {
                                    name
                                }
                                isDeprecated
                                deprecationReason
                            }
                        }
                    }
                '''
            },
            {
                'name': 'Hidden field exposure',
                'query': '''
                    {
                        __type(name: "PrivateType") {
                            name
                            fields {
                                name
                                description
                                isDeprecated
                            }
                        }
                    }
                '''
            },
            {
                'name': 'Deprecated field access',
                'query': '''
                    query {
                        __schema {
                            types {
                                fields(includeDeprecated: true) {
                                    name
                                    isDeprecated
                                    deprecationReason
                                }
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
                
                if is_schema_vulnerable(response, test):
                    findings.append({
                        "type": "GraphQL Schema Abuse",
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
        print(f"Error in GraphQL schema check: {str(e)}")
    
    return findings

def is_schema_vulnerable(response: requests.Response, test: Dict) -> bool:
    try:
        response_json = response.json()
    except json.JSONDecodeError:
        return False
    
    response_text = json.dumps(response_json).lower()
    
    # Check for schema introspection
    if test['name'] == 'Schema introspection':
        if response.status_code == 200:
            if '__schema' in response_text and 'types' in response_text:
                return True
    
    # Check for type introspection
    if test['name'] == 'Type introspection':
        if response.status_code == 200:
            if '__type' in response_text and 'fields' in response_text:
                return True
    
    # Check for hidden field exposure
    if test['name'] == 'Hidden field exposure':
        sensitive_indicators = ['private', 'internal', 'secret', 'hidden']
        if any(indicator in response_text for indicator in sensitive_indicators):
            return True
    
    # Check for deprecated field access
    if test['name'] == 'Deprecated field access':
        if 'deprecated' in response_text and 'deprecationreason' in response_text:
            return True
    
    # Check for error messages indicating schema issues
    error_indicators = [
        'introspection',
        'schema query',
        'type system',
        'metadata',
        'system fields'
    ]
    
    if any(indicator in response_text for indicator in error_indicators):
        if response.status_code < 400:
            return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_graphql_schema(
            "http://localhost:5000",
            "/graphql",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())