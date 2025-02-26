"""Pattern extraction utility for API response analysis"""
import re
from typing import Dict, List, Optional
from datetime import datetime
import uuid

class PatternExtractor:
    def __init__(self):
        self.patterns = {
            'timestamps': [
                r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?',  # ISO format
                r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?',  # Common datetime
            ],
            'identifiers': [
                r'[a-f0-9]{32}',  # MD5
                r'[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}',  # UUID
                r'[0-9a-f]{24}',  # MongoDB ObjectId
            ],
            'emails': [
                r'[\w\.-]+@[\w\.-]+\.\w+',
            ],
            'ips': [
                r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',  # IPv4
                r'([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}',  # IPv6
            ],
            'tokens': [
                r'Bearer\s+[A-Za-z0-9-._~+/]+=*',  # Bearer tokens
                r'eyJ[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*',  # JWT
            ],
            'sensitive': [
                r'password\s*[=:]\s*[^\s,]+',
                r'api[_-]?key\s*[=:]\s*[^\s,]+',
                r'secret\s*[=:]\s*[^\s,]+',
            ]
        }

    def extract_pattern(self, response: str) -> Dict[str, List[str]]:
        """Extract patterns from response content"""
        findings = {category: [] for category in self.patterns.keys()}
        
        for category, pattern_list in self.patterns.items():
            for pattern in pattern_list:
                matches = re.finditer(pattern, response, re.IGNORECASE)
                findings[category].extend([m.group() for m in matches])
                
        return findings

    def normalize_response(self, response: str) -> str:
        """Normalize response by replacing variable data with placeholders"""
        normalized = response
        
        for category, pattern_list in self.patterns.items():
            for pattern in pattern_list:
                normalized = re.sub(
                    pattern,
                    f'<{category.upper()}>',
                    normalized,
                    flags=re.IGNORECASE
                )
        
        return normalized