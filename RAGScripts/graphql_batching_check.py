#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_graphql_batching(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for GraphQL batching and complexity
        test_cases = [
            {
                'name': 'Query batching',
                'queries': [
                    {'query': 'query { user(id: 1) { name } }'},
                    {'query': 'query { user(id: 2) { name } }'},
                    {'query': 'query { user(id: 3) { name } }'}
                ]
            },
            {
                'name': 'Deep nesting',
                'query': '''
                    query {
                        user(id: 1) {
                            friends {
                                friends {
                                    friends {
                                        friends {
                                            name
                                        }
                                    }
                                }
                            }
                        }
                    }
                '''
            },
            {
                'name': 'Field multiplication',
                'query': '''
                    query {
                        user(id: 1) {
                            f1: friends { name }
                            f2: friends { name }
                            f3: friends { name }
                            f4: friends { name }
                            f5: friends { name }
                        }
                    }
                '''
            },
            {
                'name': 'Fragment cycling',
                'query': '''
                    query {
                        user(id: 1) {
                            ...UserFragment
                        }
                    }
                    fragment UserFragment on User {
                        friends {
                            ...FriendFragment
                        }
                    }
                    fragment FriendFragment on User {
                        friends {
                            ...UserFragment
                        }
                    }
                '''
            }
        ]
        
        for test in test_cases:
            try:
                if 'queries' in test:
                    # Test batch queries
                    response = requests.post(
                        test_url,
                        json=test['queries'],
                        headers={'Content-Type': 'application/json'},
                        timeout=5
                    )
                else:
                    # Test single complex query
                    response = requests.post(
                        test_url,
                        json={'query': test['query']},
                        headers={'Content-Type': 'application/json'},
                        timeout=5
                    )
                
                if is_batching_vulnerable(response, test):
                    findings.append({
                        "type": "GraphQL Query Complexity",
                        "detail": f"Potential {test['name']} vulnerability",
                        "evidence": {
                            "url": test_url,
                            "payload": test.get('queries') or test['query'],
                            "status_code": response.status_code,
                            "response": response.text[:200]
                        }
                    })
                    
            except requests.exceptions.RequestException:
                continue
                
    except Exception as e:
        print(f"Error in GraphQL batching check: {str(e)}")
    
    return findings

def is_batching_vulnerable(response: requests.Response, test: Dict) -> bool:
    try:
        response_json = response.json()
    except json.JSONDecodeError:
        return False
    
    # Check for successful batch processing
    if test['name'] == 'Query batching':
        if isinstance(response_json, list) and len(response_json) > 1:
            return True
    
    # Check for deep nesting success
    if test['name'] == 'Deep nesting':
        if response.status_code == 200 and 'data' in response_json:
            depth = str(response_json).count('friends')
            if depth >= 4:
                return True
    
    # Check for field multiplication
    if test['name'] == 'Field multiplication':
        if response.status_code == 200 and 'data' in response_json:
            if str(response_json).count('friends') >= 5:
                return True
    
    # Check for fragment cycling
    if test['name'] == 'Fragment cycling':
        if response.status_code == 200 and 'data' in response_json:
            return True
    
    # Check for performance impact indicators
    if response.elapsed.total_seconds() > 2:
        return True
    
    # Check for error messages indicating complexity issues
    error_indicators = [
        'query complexity',
        'depth limit',
        'too many fields',
        'query timeout',
        'operation too complex'
    ]
    
    response_text = json.dumps(response_json).lower()
    if any(indicator in response_text for indicator in error_indicators):
        return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_graphql_batching(
            "http://localhost:5000",
            "/graphql",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())