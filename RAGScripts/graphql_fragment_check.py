#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_graphql_fragments(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for GraphQL fragment abuse
        test_cases = [
            {
                'name': 'Fragment spreading',
                'query': '''
                    query {
                        user(id: 1) {
                            ...AdminFields
                            ...SecurityFields
                            ...InternalFields
                        }
                    }
                    
                    fragment AdminFields on User {
                        adminAccess
                        systemPrivileges
                    }
                    
                    fragment SecurityFields on User {
                        securityTokens
                        authKeys
                    }
                    
                    fragment InternalFields on User {
                        internalData
                        debugInfo
                    }
                '''
            },
            {
                'name': 'Recursive fragments',
                'query': '''
                    query {
                        node(id: "test") {
                            ...RecursiveFragment
                        }
                    }
                    
                    fragment RecursiveFragment on Node {
                        id
                        children {
                            ...RecursiveFragment
                        }
                        sensitiveData
                    }
                '''
            },
            {
                'name': 'Inline fragment type casting',
                'query': '''
                    query {
                        search(term: "admin") {
                            ... on AdminUser {
                                credentials
                                masterKey
                            }
                            ... on SystemUser {
                                rootAccess
                                systemTokens
                            }
                        }
                    }
                '''
            },
            {
                'name': 'Fragment variable leak',
                'query': '''
                    query ($role: String = "USER") {
                        ...PrivilegedFragment
                    }
                    
                    fragment PrivilegedFragment on Query {
                        secretData(role: $role) {
                            confidential
                            restricted
                        }
                        internalLogs(access: true) {
                            entries
                            debug
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
                
                if is_fragment_vulnerable(response, test):
                    findings.append({
                        "type": "GraphQL Fragment Abuse",
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
        print(f"Error in GraphQL fragment check: {str(e)}")
    
    return findings

def is_fragment_vulnerable(response: Response, test: Dict) -> bool:
    try:
        response_json = response.json()
    except json.JSONDecodeError:
        return False
    
    response_text = json.dumps(response_json).lower()
    
    # Check for fragment spreading
    if test['name'] == 'Fragment spreading':
        sensitive_fields = ['adminaccess', 'systemprivileges', 'securitytokens', 'authkeys', 'internaldata']
        if any(field in response_text for field in sensitive_fields):
            return True
    
    # Check for recursive fragment
    if test['name'] == 'Recursive fragment':
        if 'sensitivedata' in response_text and response_text.count('id') > 3:  # Arbitrary depth check
            return True
    
    # Check for inline fragment casting
    if test['name'] == 'Inline fragment type casting':
        sensitive_data = ['credentials', 'masterkey', 'rootaccess', 'systemtokens']
        if any(data in response_text for data in sensitive_data):
            return True
    
    # Check for fragment variable leak
    if test['name'] == 'Fragment variable leak':
        if ('confidential' in response_text or 'restricted' in response_text) and 'entries' in response_text:
            return True
    
    # Check for error messages indicating fragment issues
    error_indicators = [
        'fragment',
        'invalid spread',
        'type condition',
        'unknown fragment',
        'circular reference'
    ]
    
    if any(indicator in response_text for indicator in error_indicators):
        if response.status_code < 400:
            return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_graphql_fragments(
            "http://localhost:5000",
            "/graphql",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())