#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_graphql_mutations(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for GraphQL mutation abuse
        test_cases = [
            {
                'name': 'Privilege escalation mutation',
                'query': '''
                    mutation {
                        updateUserRole(userId: 1, role: "ADMIN") {
                            success
                            user {
                                role
                                permissions
                            }
                        }
                        grantAccess(userId: 1, level: "SYSTEM") {
                            granted
                            token
                        }
                    }
                '''
            },
            {
                'name': 'Data manipulation mutation',
                'query': '''
                    mutation {
                        deleteUser(id: 1) {
                            success
                        }
                        modifySystemSettings(input: {
                            debugMode: true,
                            logLevel: "DEBUG",
                            securityBypass: true
                        }) {
                            applied
                        }
                    }
                '''
            },
            {
                'name': 'Chained mutations',
                'query': '''
                    mutation {
                        step1: createToken(type: "ADMIN") {
                            token
                        }
                        step2: elevatePrivileges(token: "STOLEN_TOKEN") {
                            success
                        }
                        step3: accessSecretData(confirm: true) {
                            sensitiveInfo
                            internalData
                        }
                    }
                '''
            },
            {
                'name': 'Batch mutation injection',
                'query': '''
                    mutation {
                        m1: injectCode(input: "'; DROP TABLE users; --") {
                            status
                        }
                        m2: executeCommand(cmd: "rm -rf /") {
                            output
                        }
                        m3: modifyConfig(data: {"admin": true}) {
                            result
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
                
                if is_mutation_vulnerable(response, test):
                    findings.append({
                        "type": "GraphQL Mutation Abuse",
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
        print(f"Error in GraphQL mutation check: {str(e)}")
    
    return findings

def is_mutation_vulnerable(response: requests.Response, test: Dict) -> bool:
    try:
        response_json = response.json()
    except json.JSONDecodeError:
        return False
    
    response_text = json.dumps(response_json).lower()
    
    # Check for privilege escalation
    if test['name'] == 'Privilege escalation mutation':
        if 'success' in response_text and ('admin' in response_text or 'system' in response_text):
            return True
    
    # Check for dangerous data manipulation
    if test['name'] == 'Data manipulation mutation':
        if 'success' in response_text or 'applied' in response_text:
            if 'debugmode' in response_text or 'securitybypass' in response_text:
                return True
    
    # Check for successful chained operations
    if test['name'] == 'Chained mutations':
        if 'token' in response_text and 'success' in response_text:
            if 'sensitiveinfo' in response_text or 'internaldata' in response_text:
                return True
    
    # Check for injection success
    if test['name'] == 'Batch mutation injection':
        if 'status' in response_text or 'output' in response_text or 'result' in response_text:
            if response.status_code == 200:
                return True
    
    # Check for error messages indicating mutation issues
    error_indicators = [
        'unauthorized',
        'forbidden',
        'permission denied',
        'invalid mutation',
        'operation not allowed'
    ]
    
    if any(indicator in response_text for indicator in error_indicators):
        if response.status_code < 400:
            return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_graphql_mutations(
            "http://localhost:5000",
            "/graphql",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())