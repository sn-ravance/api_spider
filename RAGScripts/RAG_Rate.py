
#!/usr/bin/env python3
"""
Rate Limiting Test Script
Checks if an API endpoint is vulnerable to rate limiting issues
by sending rapid requests and analyzing the responses.
"""

import requests
import time
from typing import Dict, List, Optional, Any
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class RateLimitScanner(BaseScanner):
    @staticmethod
    def scan(url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        logger = setup_scanner_logger("rate_limit")
        vulnerabilities = []
        
        # Test parameters
        request_count = 50
        interval = 0.1  # 100ms between requests
        endpoint = "/books/v1"
        test_url = f"{url}{endpoint}"
        
        # Headers setup
        request_headers = headers or {}
        if token:
            request_headers['Authorization'] = f'Bearer {token}'
        
        try:
            # Send rapid requests to test rate limiting
            responses = []
            for i in range(request_count):
                response = requests.get(
                    test_url,
                    headers=request_headers,
                    timeout=5
                )
                responses.append(response.status_code)
                
                if response.status_code == 429:  # Too Many Requests
                    break
                    
                time.sleep(interval)
            
            # Analyze results
            if 429 not in responses:
                vulnerabilities.append({
                    "type": "RATE_LIMIT",
                    "severity": "MEDIUM",
                    "detail": "No rate limiting detected after sending multiple rapid requests",
                    "evidence": {
                        "request_count": len(responses),
                        "status_codes": responses
                    }
                })
                
        except requests.RequestException as e:
            logger.error(f"Error in rate limit check: {str(e)}")
            
        return vulnerabilities

scan = RateLimitScanner.scan
