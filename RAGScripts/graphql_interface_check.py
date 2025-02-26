#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_graphql_interfaces(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for GraphQL interface abuse
        test_cases = [
            {
                'name': 'Interface implementation leak',
                'query': '''
                    query {
                        node(id: "test") {
                            ... on SecretNode {
                                confidentialData
                                internalInfo
                            }
                            ... on RestrictedNode {
                                sensitiveContent
                                adminOnly
                            }
                        }
                    }
                '''
            },
            {
                'name': 'Interface type confusion',
                'query': '''
                    query {
                        search(term: "test") {
                            ... on AdminInterface {
                                privileges
                                accessLevel
                            }
                            ... on UserInterface {
                                role
                                permissions
                            }
                        }
                    }
                '''
            },
            {
                'name': 'Interface field injection',
                'query': '''
                    query {
                        entity(id: 1) {
                            __typename
                            ... on SystemInterface {
                                systemLogs
                                debugInfo
                            }
                            ... on AuditInterface {
                                auditTrail
                                securityEvents
                            }
                        }
                    }
                '''
            },
            {
                'name': 'Interface inheritance abuse',
                'query': '''
                    query {
                        resource {
                            ... on BaseInterface {
                                id
                                metadata {
                                    ... on InternalMeta {
                                        secretKey
                                        configData
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
                
                if is_interface_vulnerable(response, test):
                    findings.append({
                        "type": "GraphQL Interface Abuse",
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
        print(f"Error in GraphQL interface check: {str(e)}")
    
    return findings

def is_interface_vulnerable(response: requests.Response, test: Dict) -> bool:
    try:
        response_json = response.json()
    except json.JSONDecodeError:
        return False
    
    response_text = json.dumps(response_json).lower()
    
    # Check for interface implementation leak
    if test['name'] == 'Interface implementation leak':
        sensitive_fields = ['confidentialdata', 'internalinfo', 'sensitivecontent', 'adminonly']
        if any(field in response_text for field in sensitive_fields):
            return True
    
    # Check for interface type confusion
    if test['name'] == 'Interface type confusion':
        if response.status_code == 200:
            if ('privileges' in response_text or 'accesslevel' in response_text) and 'role' in response_text:
                return True
    
    # Check for interface field injection
    if test['name'] == 'Interface field injection':
        system_fields = ['systemlogs', 'debuginfo', 'audittrail', 'securityevents']
        if any(field in response_text for field in system_fields):
            return True
    
    # Check for interface inheritance abuse
    if test['name'] == 'Interface inheritance abuse':
        if 'secretkey' in response_text or 'configdata' in response_text:
            return True
    
    # Check for error messages indicating interface issues
    error_indicators = [
        'interface',
        'implementation',
        'type resolution',
        'abstract type',
        'invalid fragment'
    ]
    
    if any(indicator in response_text for indicator in error_indicators):
        if response.status_code < 400:
            return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_graphql_interfaces(
            "http://localhost:5000",
            "/graphql",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())