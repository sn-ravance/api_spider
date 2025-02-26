#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
import re
from RAGScripts.utils.logger import setup_scanner_logger

async def check_info_leakage(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Patterns that might indicate sensitive data
        sensitive_patterns = {
            "password": r'(?i)(password|passwd|pwd)[\'"]\s*:\s*[\'"][^\'"]+[\'"]',
            "token": r'(?i)(token|jwt|bearer)[\'"]\s*:\s*[\'"][^\'"]+[\'"]',
            "api_key": r'(?i)(api[_-]?key|access[_-]?key)[\'"]\s*:\s*[\'"][^\'"]+[\'"]',
            "secret": r'(?i)(secret|private)[\'"]\s*:\s*[\'"][^\'"]+[\'"]',
            "private_key": r'(?i)(private[_-]?key|rsa|ssh[_-]?key)[\'"]\s*:\s*[\'"][^\'"]+[\'"]',
            "credentials": r'(?i)(credentials|auth)[\'"]\s*:\s*\{[^\}]+\}',
            "internal_paths": r'(?i)(\/var\/|\/etc\/|\/usr\/|\/home\/|\\Windows\\|C:\\)',
            "email": r'[\w\.-]+@[\w\.-]+\.\w+',
            "ip_address": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            "stack_trace": r'(?i)(stack trace|stacktrace|stack_trace|at\s+[\w\.$]+\([^\)]*\))',
            "debug_info": r'(?i)(debug|verbose|trace)[\'"]\s*:\s*(true|1)',
            "internal_ids": r'(?i)(user_id|account_id|customer_id)[\'"]\s*:\s*\d+'
        }
        
        # Headers that might indicate debug/verbose modes
        debug_headers = [
            'X-Debug',
            'X-Debug-Mode',
            'Debug',
            'Verbose',
            'Dev-Mode'
        ]
        
        # Test with debug headers
        for debug_header in debug_headers:
            try:
                headers = {'Accept': '*/*', debug_header: 'true'}
                response = requests.get(test_url, headers=headers, timeout=5)
                
                # Check response for sensitive data patterns
                found_patterns = []
                for pattern_name, pattern in sensitive_patterns.items():
                    matches = re.findall(pattern, response.text)
                    if matches:
                        found_patterns.append({
                            "type": pattern_name,
                            "matches": matches[:3]  # Limit to first 3 matches
                        })
                
                if found_patterns:
                    findings.append({
                        "type": "Information Exposure",
                        "name": "Sensitive Data Exposure",
                        "detail": f"Endpoint exposes sensitive information with {debug_header}",
                        "evidence": {
                            "url": test_url,
                            "method": method,
                            "header_used": debug_header,
                            "patterns_found": found_patterns
                        },
                        "severity": "HIGH"
                    })
                
                # Check for sensitive headers in response
                sensitive_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-runtime']
                exposed_headers = {}
                
                for header in sensitive_headers:
                    if header in response.headers:
                        exposed_headers[header] = response.headers[header]
                
                if exposed_headers:
                    findings.append({
                        "type": "Information Exposure",
                        "name": "Sensitive Header Exposure",
                        "detail": "Response contains sensitive headers",
                        "evidence": {
                            "url": test_url,
                            "method": method,
                            "exposed_headers": exposed_headers
                        },
                        "severity": "MEDIUM"
                    })
                
            except requests.exceptions.RequestException:
                continue
        
        # Check original response
        found_patterns = []
        for pattern_name, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, initial_response.text)
            if matches:
                found_patterns.append({
                    "type": pattern_name,
                    "matches": matches[:3]
                })
        
        if found_patterns:
            findings.append({
                "type": "Information Exposure",
                "name": "Default Response Data Exposure",
                "detail": "Endpoint exposes sensitive information in default response",
                "evidence": {
                    "url": test_url,
                    "method": method,
                    "patterns_found": found_patterns
                },
                "severity": "HIGH"
            })
    
    except Exception as e:
        print(f"Error in information leakage check: {str(e)}")
    
    return findings