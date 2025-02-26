#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin, parse_qs, urlparse
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_parameter_pollution(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        parsed_url = urlparse(test_url)
        original_params = parse_qs(parsed_url.query)
        
        # Test cases for parameter pollution
        test_cases = [
            {
                'name': 'Duplicate parameters',
                'params': {k: v * 2 for k, v in original_params.items()}
            },
            {
                'name': 'Case variation',
                'params': {k.upper(): v for k, v in original_params.items()}
            },
            {
                'name': 'Array notation',
                'params': {f"{k}[]": v for k, v in original_params.items()}
            },
            {
                'name': 'Mixed encoding',
                'params': {k: [v[0], v[0].encode('utf-16').decode('utf-16')] 
                          for k, v in original_params.items()}
            }
        ]
        
        for test in test_cases:
            try:
                response = requests.request(
                    method,
                    test_url,
                    params=test['params'],
                    headers={'Content-Type': 'application/json'},
                    timeout=5
                )
                
                if is_parameter_pollution_vulnerable(response, initial_response, test):
                    findings.append({
                        "type": "Parameter Pollution",
                        "detail": f"Potential {test['name']} vulnerability",
                        "evidence": {
                            "url": test_url,
                            "original_params": original_params,
                            "polluted_params": test['params'],
                            "status_code": response.status_code,
                            "response": response.text[:200]
                        }
                    })
                    
            except requests.exceptions.RequestException:
                continue
                
    except Exception as e:
        print(f"Error in parameter pollution check: {str(e)}")
    
    return findings

def is_parameter_pollution_vulnerable(response: requests.Response, initial_response: requests.Response, test: Dict) -> bool:
    # Check for parameter pollution indicators
    
    # Check for successful processing of polluted parameters
    if response.status_code == 200:
        # Different response length might indicate parameter acceptance
        if len(response.text) != len(initial_response.text):
            return True
    
    # Check for error messages that might indicate parameter handling issues
    error_indicators = [
        'duplicate parameter',
        'invalid parameter',
        'parameter error',
        'multiple values',
        'unexpected array'
    ]
    
    response_text = response.text.lower()
    if any(indicator in response_text for indicator in error_indicators):
        if response.status_code < 400:
            return True
    
    # Check for reflected parameters
    for param_value in str(test['params']).lower().split():
        if param_value in response_text:
            return True
    
    # Check for unusual response patterns
    if test['name'] == 'Duplicate parameters':
        # Look for doubled values in response
        for value in test['params'].values():
            if str(value).lower() in response_text:
                return True
    
    # Check for case-sensitive parameter handling
    if test['name'] == 'Case variation':
        if response.status_code == initial_response.status_code:
            return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_parameter_pollution(
            "http://localhost:5000",
            "/api/test?id=123&type=user",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())