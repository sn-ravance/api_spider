from typing import Dict, List
import re
import json
from datetime import datetime

class CognitiveAnalyzer:
    def __init__(self):
        self.response_history = []
        self.vulnerability_patterns = {
            'pii_disclosure': {
                'fields': ['email', 'phone', 'address', 'name', 'ssn', 'dob'],
                'patterns': [
                    r'\b[\w\.-]+@[\w\.-]+\.\w+\b',
                    r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
                    r'\b\d{3}[-]?\d{2}[-]?\d{4}\b'
                ]
            },
            'debug_info': {
                'endpoints': ['debug', '_debug', 'test', 'dev'],
                'indicators': ['password', 'secret', 'token', 'admin']
            },
            'privilege_escalation': {
                'fields': ['admin', 'role', 'permission', 'access_level'],
                'values': ['true', '1', 'yes']
            },
            'sql_injection': {
                'error_patterns': [
                    'sql syntax',
                    'operational error',
                    'sqlite3.OperationalError',
                    'unrecognized token'
                ]
            }
        }

    def analyze_endpoint(self, url: str, method: str, response: Dict) -> List[Dict]:
        findings = []
        
        # Check for PII disclosure
        pii_finding = self._check_pii_disclosure(response)
        if pii_finding:
            findings.append(pii_finding)
            
        # Check for debug information
        debug_finding = self._check_debug_info(url, response)
        if debug_finding:
            findings.append(debug_finding)
            
        # Check for privilege escalation
        priv_finding = self._check_privilege_escalation(response)
        if priv_finding:
            findings.append(priv_finding)
            
        # Check for SQL injection
        sql_finding = self._check_sql_injection(response)
        if sql_finding:
            findings.append(sql_finding)
            
        return findings

    def _check_pii_disclosure(self, response: Dict) -> Dict:
        content = str(response.get('body', ''))
        patterns = self.vulnerability_patterns['pii_disclosure']
        
        found_pii = []
        for pattern in patterns['patterns']:
            matches = re.findall(pattern, content)
            if matches:
                found_pii.extend(matches[:3])  # Limit to first 3 matches
                
        if found_pii:
            return {
                'type': 'PII_DISCLOSURE',
                'severity': 'HIGH',
                'detail': 'PII data exposed without authorization',
                'evidence': found_pii
            }
        return None

    def _check_debug_info(self, url: str, response: Dict) -> Dict:
        patterns = self.vulnerability_patterns['debug_info']
        
        # Check if endpoint contains debug indicators
        if any(debug in url.lower() for debug in patterns['endpoints']):
            # Check for sensitive data in debug output
            if any(indicator in str(response).lower() for indicator in patterns['indicators']):
                return {
                    'type': 'DEBUG_INFO_EXPOSURE',
                    'severity': 'CRITICAL',
                    'detail': 'Debug endpoint exposing sensitive information',
                    'evidence': url
                }
        return None
        
    def analyze_json_structure(self, data: Dict) -> List[str]:
        indicators = []
        
        # Check for sensitive data patterns
        sensitive_fields = ["password", "token", "secret", "key"]
        found_fields = self._find_sensitive_fields(data, sensitive_fields)
        if found_fields:
            indicators.append(f"Sensitive data exposure: {', '.join(found_fields)}")
            
        # Check for error messages
        error_patterns = ["error", "exception", "stack", "trace"]
        if self._contains_patterns(str(data), error_patterns):
            indicators.append("Error message disclosure")
            
        return indicators
        
    def learn_from_response(self, response, scenario: str) -> None:
        """Learn from successful and failed attempts"""
        self.response_history.append({
            "scenario": scenario,
            "status_code": response.status_code,
            "response": response.text,
            "timestamp": datetime.now()
        })
        
        # Update patterns based on successful exploits
        if response.status_code == 200:
            if scenario == "auth_bypass":
                self.learned_patterns["auth_bypass"].add(
                    self._extract_pattern(response.text)
                )
                
    def _find_sensitive_fields(self, data: Dict, patterns: List[str]) -> List[str]:
        found = []
        if isinstance(data, dict):
            for key, value in data.items():
                if any(pattern in key.lower() for pattern in patterns):
                    found.append(key)
                if isinstance(value, (dict, list)):
                    found.extend(self._find_sensitive_fields(value, patterns))
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    found.extend(self._find_sensitive_fields(item, patterns))
        return found
        
    def _contains_patterns(self, text: str, patterns: List[str]) -> bool:
        return any(pattern in text.lower() for pattern in patterns)
        
    def _extract_pattern(self, text: str) -> str:
        # Extract meaningful patterns from successful responses
        return re.sub(r'[0-9]+', 'N', text)[:50]