from typing import Dict, List, Optional
import requests
import json
from .base_scanner import BaseScanner
from .utils.cognitive_analyzer import CognitiveAnalyzer

class ScannerTemplate(BaseScanner):
    def __init__(self):
        super().__init__("scanner_name")
        self.cognitive = CognitiveAnalyzer()
        self.response_patterns = {
            "auth_bypass": ["unauthorized", "forbidden", "invalid token"],
            "injection": ["syntax error", "mongodb", "mysql", "sqlite"],
            "info_disclosure": ["stack trace", "debug", "internal server"],
            "role_bypass": ["admin", "role", "permission"]
        }
        
    def analyze_response(self, response, context: Dict) -> Dict:
        analysis = {
            "anomalies": [],
            "confidence": 0.0,
            "indicators": []
        }
        
        # Analyze status code patterns
        if response.status_code == 200 and context.get("requires_auth", True):
            analysis["anomalies"].append("Unexpected 200 response for protected endpoint")
            
        # Analyze response content
        try:
            json_response = response.json()
            analysis["indicators"].extend(
                self.cognitive.analyze_json_structure(json_response)
            )
        except json.JSONDecodeError:
            # Check for HTML/text responses that might indicate vulnerabilities
            if "<!doctype html>" in response.text.lower():
                analysis["anomalies"].append("HTML response from API endpoint")
                
        return analysis
        
    def scan(self, url: str, method: str, token: Optional[str] = None) -> List[Dict]:
        results = []
        
        # Define test scenarios
        scenarios = [
            {"name": "baseline", "headers": {}},
            {"name": "auth_bypass", "headers": {"Authorization": "Bearer invalid"}},
            {"name": "role_injection", "headers": {"Role": "admin"}},
            {"name": "nosql_injection", "headers": {}, "params": {"id": {"$ne": null}}},
        ]
        
        for scenario in scenarios:
            try:
                headers = scenario["headers"]
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                    
                response = requests.request(
                    method, 
                    url,
                    headers=headers,
                    params=scenario.get("params", {}),
                    timeout=10
                )
                
                # Cognitive analysis of response
                analysis = self.analyze_response(response, {
                    "scenario": scenario["name"],
                    "requires_auth": True
                })
                
                if analysis["anomalies"] or analysis["indicators"]:
                    results.append({
                        "type": f"POTENTIAL_{scenario['name'].upper()}_VULNERABILITY",
                        "severity": "HIGH",
                        "detail": f"Potential vulnerability found in {scenario['name']} scenario",
                        "evidence": {
                            "url": url,
                            "method": method,
                            "scenario": scenario["name"],
                            "headers": headers,
                            "status_code": response.status_code,
                            "response": response.text[:500],
                            "analysis": analysis
                        }
                    })
                    
                # Learn from response
                self.cognitive.learn_from_response(response, scenario["name"])
                    
            except requests.RequestException as e:
                self.logger.error(f"Request failed in {scenario['name']}: {e}")
            
        return results