#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_graphql_introspection(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for GraphQL introspection abuse
        test_cases = [
            {
                'name': 'Full schema introspection',
                'query': '''
                    query IntrospectionQuery {
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
                            queryType {
                                fields {
                                    name
                                    description
                                }
                            }
                            mutationType {
                                fields {
                                    name
                                    description
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
                'name': 'Directive introspection',
                'query': '''
                    query {
                        __schema {
                            directives {
                                name
                                description
                                locations
                                args {
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
                'name': 'Hidden field introspection',
                'query': '''
                    query {
                        __type(name: "AdminSettings") {
                            name
                            fields {
                                name
                                type {
                                    name
                                    fields {
                                        name
                                    }
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
                
                if is_introspection_vulnerable(response, test):
                    findings.append({
                        "type": "GraphQL Introspection Abuse",
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
        print(f"Error in GraphQL introspection check: {str(e)}")
    
    return findings

def is_introspection_vulnerable(response: requests.Response, test: Dict) -> bool:
    try:
        response_json = response.json()
    except json.JSONDecodeError:
        return False
    
    response_text = json.dumps(response_json).lower()
    
    # Check for full schema exposure
    if test['name'] == 'Full schema introspection':
        if '__schema' in response_text and 'querytype' in response_text:
            if 'mutationtype' in response_text or 'fields' in response_text:
                return True
    
    # Check for type information exposure
    if test['name'] == 'Type introspection':
        if '__type' in response_text and 'fields' in response_text:
            if 'isdeprecated' in response_text or 'deprecationreason' in response_text:
                return True
    
    # Check for directive information exposure
    if test['name'] == 'Directive introspection':
        if 'directives' in response_text and 'locations' in response_text:
            if 'args' in response_text or 'description' in response_text:
                return True
    
    # Check for hidden field exposure
    if test['name'] == 'Hidden field introspection':
        sensitive_types = ['admin', 'internal', 'secret', 'system']
        if '__type' in response_text and any(t in response_text for t in sensitive_types):
            return True
    
    # Check for error messages indicating introspection issues
    error_indicators = [
        'introspection',
        'schema query',
        'type query',
        'metadata query',
        'disabled feature'
    ]
    
    if any(indicator in response_text for indicator in error_indicators):
        if response.status_code < 400:
            return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_graphql_introspection(
            "http://localhost:5000",
            "/graphql",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())