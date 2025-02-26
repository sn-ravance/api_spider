#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_graphql_directives(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for GraphQL directive abuse
        test_cases = [
            {
                'name': 'Directive bypass',
                'query': '''
                    query {
                        sensitiveData @skip(if: false) {
                            internalInfo
                            secretKeys
                        }
                        restrictedData @include(if: true) {
                            adminData
                            systemLogs
                        }
                    }
                '''
            },
            {
                'name': 'Custom directive injection',
                'query': '''
                    query {
                        user(id: 1) @custom(role: "ADMIN") {
                            email
                            password
                            @deprecated(reason: "security")
                        }
                    }
                '''
            },
            {
                'name': 'Directive chaining',
                'query': '''
                    query {
                        data 
                        @skip(if: false) 
                        @include(if: true) 
                        @custom(bypass: true) {
                            protectedField
                            secretField
                        }
                    }
                '''
            },
            {
                'name': 'Directive argument manipulation',
                'query': '''
                    query {
                        users @access(level: "SYSTEM") {
                            adminView @role(require: "NONE") {
                                credentials
                                tokens
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
                
                if is_directive_vulnerable(response, test):
                    findings.append({
                        "type": "GraphQL Directive Abuse",
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
        print(f"Error in GraphQL directive check: {str(e)}")
    
    return findings

def is_directive_vulnerable(response: requests.Response, test: Dict) -> bool:
    try:
        response_json = response.json()
    except json.JSONDecodeError:
        return False
    
    response_text = json.dumps(response_json).lower()
    
    # Check for directive bypass
    if test['name'] == 'Directive bypass':
        sensitive_fields = ['internalinfo', 'secretkeys', 'admindata', 'systemlogs']
        if any(field in response_text for field in sensitive_fields):
            return True
    
    # Check for custom directive injection
    if test['name'] == 'Custom directive injection':
        if 'password' in response_text or 'email' in response_text:
            return True
    
    # Check for directive chaining
    if test['name'] == 'Directive chaining':
        if 'protectedfield' in response_text or 'secretfield' in response_text:
            return True
    
    # Check for directive argument manipulation
    if test['name'] == 'Directive argument manipulation':
        if 'credentials' in response_text or 'tokens' in response_text:
            return True
    
    # Check for error messages indicating directive issues
    error_indicators = [
        'directive',
        'invalid argument',
        'unknown directive',
        'directive not allowed',
        'invalid directive'
    ]
    
    if any(indicator in response_text for indicator in error_indicators):
        if response.status_code < 400:
            return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_graphql_directives(
            "http://localhost:5000",
            "/graphql",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())