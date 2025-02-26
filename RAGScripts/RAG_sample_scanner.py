#!/usr/bin/env python3
import argparse
import json
import uuid
from datetime import datetime

def main():
    parser = argparse.ArgumentParser(description='Sample RAG Security Scanner')
    parser.add_argument('--target', required=True, help='Target API endpoint')
    parser.add_argument('--auth', required=True, help='Authentication details in JSON format')
    
    args = parser.parse_args()
    
    # Sample finding
    finding = {
        "id": str(uuid.uuid4()),
        "title": "Sample Security Finding",
        "description": "This is a sample security finding for testing purposes",
        "endpoint": args.target,
        "severity": {
            "level": "tier1",
            "description": "Tier 1 Validator - Intermediate threats, Some customization, Basic chaining"
        },
        "impact": "This is a sample impact description",
        "request": {
            "headers": {"Content-Type": "application/json"},
            "body": "{}",
            "method": "GET"
        },
        "response": {
            "headers": {"Content-Type": "application/json"},
            "body": "{}",
            "statusCode": 200
        },
        "remediation": "This is a sample remediation step",
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # Output JSON to stdout (this will be captured by the Node.js process)
    print(json.dumps([finding]))

if __name__ == "__main__":
    main()
