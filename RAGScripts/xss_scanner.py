#!/usr/bin/env python3
import sys
import json
import requests
from urllib.parse import urljoin

def scan_for_xss(target_url):
    try:
        # Basic test payload
        test_payload = "<script>alert(1)</script>"
        
        # Test endpoints
        endpoints = [
            "/search",
            "/feedback",
            "/comment"
        ]
        
        findings = []
        
        for endpoint in endpoints:
            url = urljoin(target_url, endpoint)
            try:
                # Test GET parameter
                test_url = f"{url}?q={test_payload}"
                response = requests.get(test_url, timeout=5)
                
                if test_payload in response.text:
                    findings.append({
                        "severity": "high",
                        "category": "xss",
                        "description": f"Potential XSS vulnerability found in {endpoint}",
                        "evidence": f"Payload was reflected: {test_payload}",
                        "location": endpoint,
                        "recommendation": "Implement proper input validation and output encoding"
                    })
            except requests.RequestException:
                continue
        
        return {
            "target": target_url,
            "scanner": "xss_scanner",
            "findings": findings,
            "metadata": {
                "endpoints_tested": len(endpoints),
                "timestamp": "2024-02-17T00:00:00Z"
            }
        }
        
    except Exception as e:
        return {
            "error": str(e),
            "target": target_url,
            "scanner": "xss_scanner"
        }

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Target URL required"}))
        sys.exit(1)
        
    target = sys.argv[1]
    results = scan_for_xss(target)
    print(json.dumps(results))
