"""LLM prompt templates with few-shot examples"""

SECURITY_ANALYSIS_TEMPLATE = """Analyze this API endpoint for security vulnerabilities:

Context:
- URL: {url}
- Response Pattern: {pattern}
- Historical Vulnerabilities: {history}
- Known False Positives: {false_positives}

Step-by-step Analysis:
1. Authentication/Authorization:
   - Check for missing or weak auth mechanisms
   - Identify privilege escalation risks
   - Evaluate token handling

2. Information Disclosure:
   - Examine error messages
   - Look for sensitive data leaks
   - Check response headers

3. Input Validation:
   - Assess parameter handling
   - Look for injection risks
   - Verify content-type enforcement

4. Error Handling:
   - Evaluate error verbosity
   - Check for stack traces
   - Assess error consistency

5. Access Control:
   - Review resource isolation
   - Check for IDOR vulnerabilities
   - Evaluate rate limiting

Examples:
1. Genuine Vulnerability:
   Request: GET /api/users/123
   Response: {"error": "Invalid user ID", "stack": "at User.findById..."}
   Analysis: Information disclosure via stack trace exposure

2. False Positive:
   Request: POST /api/auth
   Response: {"error": "Invalid credentials"}
   Analysis: Expected authentication error, not a vulnerability

Provide your analysis in the following format:
{
    "security_score": float,  // 0.0 to 1.0
    "vulnerabilities": [
        {
            "type": string,
            "severity": string,
            "description": string,
            "confidence": float,
            "false_positive_risk": float,
            "reasoning": string
        }
    ],
    "recommendations": [string],
    "analysis_steps": [string]
}
"""

BEHAVIOR_ANALYSIS_TEMPLATE = """Analyze this API endpoint's behavior:

Context:
- URL: {url}
- Responses: {responses}
- Current Behavior: {behavior}
- Historical Patterns: {patterns}

Step-by-step Analysis:
1. Response Consistency
   - Compare status codes
   - Analyze response formats
   - Check error handling patterns

2. Authentication Patterns
   - Identify auth requirements
   - Evaluate token usage
   - Check session handling

3. Data Validation
   - Review input handling
   - Check sanitization
   - Assess type enforcement

4. Performance Characteristics
   - Response times
   - Resource usage
   - Rate limiting

Examples:
1. Normal Pattern:
   Pattern: Consistent 401 for missing auth
   Analysis: Expected behavior for protected endpoint

2. Anomaly:
   Pattern: Mixed 200/500 for same input
   Analysis: Potential stability issue

Provide your analysis in JSON format.
"""

METHOD_ANALYSIS_TEMPLATE = """Suggest appropriate HTTP methods for this endpoint:

Context:
- URL: {url}
- Current Behavior: {behavior}
- Resource Type: {resource_type}

Consider:
1. RESTful Design:
   - Resource identification
   - State modifications
   - Collection vs item operations

2. Idempotency:
   - Safe methods (GET, HEAD)
   - Idempotent methods (PUT, DELETE)
   - Non-idempotent (POST, PATCH)

3. Security Implications:
   - Method restrictions
   - CORS considerations
   - Method override risks

Examples:
1. User Resource:
   GET /users/{id} - Retrieve user
   PUT /users/{id} - Update user
   DELETE /users/{id} - Remove user

2. Collection Resource:
   GET /articles - List articles
   POST /articles - Create article

Provide your analysis in JSON format.
"""

# Add more templates as needed