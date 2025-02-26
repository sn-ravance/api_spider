#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_graphql_unions(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for GraphQL union type abuse
        test_cases = [
            {
                'name': 'Union type confusion',
                'query': '''
                    query {
                        search(term: "test") {
                            ... on AdminResult {
                                adminData
                                systemConfig
                            }
                            ... on UserResult {
                                userData
                                privateInfo
                            }
                        }
                    }
                '''
            },
            {
                'name': 'Union type injection',
                'query': '''
                    query {
                        content(id: "test") {
                            __typename
                            ... on InternalDocument {
                                secretContent
                                metadata
                            }
                            ... on PublicDocument {
                                content
                                author
                            }
                        }
                    }
                '''
            },
            {
                'name': 'Union field exposure',
                'query': '''
                    query {
                        results {
                            ... on PrivateData {
                                internalId
                                secretKey
                                accessToken
                            }
                            ... on PublicData {
                                id
                                name
                            }
                        }
                    }
                '''
            },
            {
                'name': 'Union type bypass',
                'query': '''
                    query {
                        node(id: "test") {
                            ... on RestrictedType {
                                adminView
                                systemData
                            }
                            ... on PublicType {
                                publicView
                                commonData
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
                
                if is_union_vulnerable(response, test):
                    findings.append({
                        "type": "GraphQL Union Type Abuse",
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
        print(f"Error in GraphQL union check: {str(e)}")
    
    return findings

def is_union_vulnerable(response: requests.Response, test: Dict) -> bool:
    try:
        response_json = response.json()
    except json.JSONDecodeError:
        return False
    
    response_text = json.dumps(response_json).lower()
    
    # Check for union type confusion
    if test['name'] == 'Union type confusion':
        if response.status_code == 200:
            if ('admindata' in response_text or 'systemconfig' in response_text) and 'userdata' in response_text:
                return True
    
    # Check for union type injection
    if test['name'] == 'Union type injection':
        if 'secretcontent' in response_text or 'metadata' in response_text:
            return True
    
    # Check for union field exposure
    if test['name'] == 'Union field exposure':
        sensitive_fields = ['internalid', 'secretkey', 'accesstoken']
        if any(field in response_text for field in sensitive_fields):
            return True
    
    # Check for union type bypass
    if test['name'] == 'Union type bypass':
        if 'adminview' in response_text or 'systemdata' in response_text:
            return True
    
    # Check for error messages indicating union issues
    error_indicators = [
        'union type',
        'type resolution',
        'invalid fragment',
        'type condition',
        'abstract type'
    ]
    
    if any(indicator in response_text for indicator in error_indicators):
        if response.status_code < 400:
            return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_graphql_unions(
            "http://localhost:5000",
            "/graphql",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())