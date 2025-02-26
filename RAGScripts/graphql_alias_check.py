#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_graphql_aliases(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for GraphQL alias abuse
        test_cases = [
            {
                'name': 'Alias field duplication',
                'query': '''
                    query {
                        normalUser: user(id: 1) {
                            id
                            name
                        }
                        adminUser: user(id: 1) {
                            password
                            secretKey
                        }
                        superUser: user(id: 1) {
                            internalData
                            systemAccess
                        }
                    }
                '''
            },
            {
                'name': 'Alias permission bypass',
                'query': '''
                    query {
                        public: userData(id: 1) {
                            basic: profile
                        }
                        private: userData(id: 1) {
                            sensitive: adminProfile
                            restricted: securitySettings
                        }
                    }
                '''
            },
            {
                'name': 'Alias nested exposure',
                'query': '''
                    query {
                        data: sensitiveNode {
                            visible: publicInfo {
                                id
                                name
                            }
                            hidden: privateInfo {
                                credentials
                                apiKeys
                            }
                        }
                    }
                '''
            },
            {
                'name': 'Alias chain attack',
                'query': '''
                    query {
                        a1: adminAccess {
                            b1: bypassCheck {
                                c1: configData
                                d1: debugInfo
                            }
                        }
                        a2: systemAccess {
                            b2: internalData {
                                c2: secretData
                                d2: logsData
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
                
                if is_alias_vulnerable(response, test):
                    findings.append({
                        "type": "GraphQL Alias Abuse",
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
        print(f"Error in GraphQL alias check: {str(e)}")
    
    return findings

def is_alias_vulnerable(response: requests.Response, test: Dict) -> bool:
    try:
        response_json = response.json()
    except json.JSONDecodeError:
        return False
    
    response_text = json.dumps(response_json).lower()
    
    # Check for alias field duplication
    if test['name'] == 'Alias field duplication':
        sensitive_fields = ['password', 'secretkey', 'internaldata', 'systemaccess']
        if any(field in response_text for field in sensitive_fields):
            return True
    
    # Check for alias permission bypass
    if test['name'] == 'Alias permission bypass':
        if 'adminprofile' in response_text or 'securitysettings' in response_text:
            return True
    
    # Check for alias nested exposure
    if test['name'] == 'Alias nested exposure':
        if 'credentials' in response_text or 'apikeys' in response_text:
            return True
    
    # Check for alias chain attack
    if test['name'] == 'Alias chain attack':
        sensitive_data = ['configdata', 'debuginfo', 'secretdata', 'logsdata']
        if any(data in response_text for data in sensitive_data):
            return True
    
    # Check for error messages indicating alias issues
    error_indicators = [
        'alias',
        'duplicate field',
        'field collision',
        'naming conflict',
        'invalid alias'
    ]
    
    if any(indicator in response_text for indicator in error_indicators):
        if response.status_code < 400:
            return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_graphql_aliases(
            "http://localhost:5000",
            "/graphql",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())