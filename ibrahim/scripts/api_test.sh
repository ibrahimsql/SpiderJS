#!/bin/bash

# API Test Script for SpiderJS
# This script tests the basic API endpoints for SpiderJS

# Set the base URL
BASE_URL="http://localhost:8080/api/v1"

# Set colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Function to test an endpoint
test_endpoint() {
    local endpoint=$1
    local method=$2
    local expected_status=$3
    local payload=$4

    echo -e "${YELLOW}Testing ${method} ${endpoint}...${NC}"
    
    # Make the request
    if [ "$method" == "GET" ]; then
        response=$(curl -s -o response.txt -w "%{http_code}" -X GET "${BASE_URL}${endpoint}")
    elif [ "$method" == "POST" ]; then
        if [ -z "$payload" ]; then
            response=$(curl -s -o response.txt -w "%{http_code}" -X POST "${BASE_URL}${endpoint}")
        else
            response=$(curl -s -o response.txt -w "%{http_code}" -X POST -H "Content-Type: application/json" -d "${payload}" "${BASE_URL}${endpoint}")
        fi
    else
        echo -e "${RED}Unsupported method: ${method}${NC}"
        return 1
    fi
    
    # Check the status code
    if [ "$response" -eq "$expected_status" ]; then
        echo -e "${GREEN}✓ Status code is ${response} as expected${NC}"
    else
        echo -e "${RED}✗ Status code is ${response}, expected ${expected_status}${NC}"
    fi
    
    # Print the response body
    echo "Response body:"
    cat response.txt | jq . 2>/dev/null || cat response.txt
    echo
}

# Main test script
echo "=== SpiderJS API Test ==="
echo "Testing against base URL: ${BASE_URL}"
echo

# Test health endpoint
test_endpoint "/health" "GET" 200

# Test version endpoint
test_endpoint "/version" "GET" 200

# Test scan endpoint
test_endpoint "/scan" "POST" 202 '{"url": "https://example.com"}'

# Test get scan results endpoint
test_endpoint "/scan/scan-123456" "GET" 200

# Test cancel scan endpoint
test_endpoint "/scan/scan-123456/cancel" "POST" 200

# Test analyze endpoint
test_endpoint "/analyze" "POST" 200 '{"url": "https://example.com/bundle.js"}'

# Test predict endpoint
test_endpoint "/ml/predict" "POST" 200 '{"code": "function test() { var input = document.getElementById(\"input\").value; eval(input); }"}'

# Clean up
rm -f response.txt

echo "=== API Test Complete ===" 