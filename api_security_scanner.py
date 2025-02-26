#!/usr/bin/env python3

import yaml
import asyncio
from typing import Dict, List, Any, Optional
import importlib
import inspect
from urllib.parse import urljoin
import requests
import logging
import json
import time

# Import security check modules
from RAGScripts.RAG_SQLi import SQLiScanner
from RAGScripts.RAG_unauthorized_password_change import UnauthorizedPasswordChangeScanner
from RAGScripts.RAG_BOLA import BOLAScanner
from RAGScripts.RAG_MassAssign import MassAssignmentScanner
from RAGScripts.RAG_Leak import DataExposureScanner
from RAGScripts.RAG_UserPass import UserPassEnumScanner
from RAGScripts.RAG_RegexDoS import RegexDOSScanner
from RAGScripts.RAG_Rate import RateLimitScanner
from RAGScripts.RAG_jwt_bypass import JWTBypassScanner

def setup_logging(verbosity: int = 1) -> logging.Logger:
    logger = logging.getLogger('api_security_scanner')
    
    if verbosity == 1:
        level = logging.INFO
    elif verbosity == 2:
        level = logging.DEBUG
    elif verbosity >= 3:
        level = logging.DEBUG
    else:
        level = logging.WARNING
    
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(level)
    
    return logger

class APISecurityScanner:
    def __init__(self, spec_file: str, target_url: str, verbosity: int = 1, token: Optional[str] = None):
        self.spec_file = spec_file
        self.target_url = target_url
        self.logger = setup_logging(verbosity)
        self.spec = self._load_spec()
        self.discovery_cache = {}
        self.headers = {}
        if token:
            self.headers['Authorization'] = f'Bearer {token}'
            self.logger.info("Using provided bearer token for authenticated requests")
        self.security_checks = [
            SQLiScanner,
            UnauthorizedPasswordChangeScanner,
            BOLAScanner,
            MassAssignmentScanner,
            DataExposureScanner,
            UserPassEnumScanner,
            RegexDOSScanner,
            RateLimitScanner,
            JWTBypassScanner
        ]

    def _load_spec(self) -> Dict:
        try:
            with open(self.spec_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            self.logger.error(f"Error loading spec file: {str(e)}")
            raise

    def scan_endpoint(self, path: str, methods: Dict[str, Any]) -> List[Dict]:
        findings = []
        try:
            endpoint_url = urljoin(self.target_url, path)

            for method, details in methods.items():
                self.logger.info(f"Scanning endpoint: {method} {endpoint_url}")
                
                try:
                    response = requests.request(method, endpoint_url, headers=self.headers)
                    
                    for check in self.security_checks:
                        try:
                            if isinstance(check, type):
                                scanner = check()
                                check_findings = scanner.scan(endpoint_url, method, path, response, headers=self.headers)
                            else:
                                check_findings = check(endpoint_url, method, path, response, headers=self.headers)
                                
                            if check_findings:
                                findings.extend(check_findings)
                        except Exception as e:
                            self.logger.error(f"Error in security check {check.__name__ if hasattr(check, '__name__') else type(check).__name__}: {str(e)}")
                            continue
                            
                except requests.RequestException as e:
                    self.logger.error(f"Error accessing endpoint {endpoint_url}: {str(e)}")
                    continue

            return findings
        except Exception as e:
            self.logger.error(f"Error scanning endpoint {path}: {str(e)}")
            return findings

    def scan_api(self) -> List[Dict]:
        all_findings = []
        paths = self.spec.get('paths', {})

        for path, methods in paths.items():
            try:
                findings = self.scan_endpoint(path, methods)
                all_findings.extend(findings)
            except Exception as e:
                self.logger.error(f"Error scanning path {path}: {str(e)}")
                continue

        return all_findings

    def run(self) -> List[Dict]:
        start_time = time.time()
        self.logger.info(f"Starting security scan of {self.target_url}")

        try:
            findings = self.scan_api()
            elapsed = time.time() - start_time
            self.logger.info(f"Scan completed in {elapsed:.2f}s with {len(findings)} findings")
            return findings

        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            raise

def main():
    import argparse
    parser = argparse.ArgumentParser(description='API Security Scanner')
    parser.add_argument('spec_file', help='Path to OpenAPI specification file')
    parser.add_argument('target_url', help='Target API base URL')
    parser.add_argument('-v', '--verbosity', type=int, default=1, help='Verbosity level (1-3)')
    parser.add_argument('--token', help='Bearer token for authenticated requests')
    parser.add_argument('-o', '--output', help='Output file for findings')
    
    args = parser.parse_args()
    
    scanner = APISecurityScanner(
        spec_file=args.spec_file,
        target_url=args.target_url,
        verbosity=args.verbosity,
        token=args.token
    )
    
    findings = scanner.run()
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(findings, f, indent=2)
    else:
        print(json.dumps(findings, indent=2))

if __name__ == '__main__':
    main()