#!/bin/bash
# run-tests.sh - Test runner for IPCrypt Lua implementation

set -e

echo "================================"
echo "IPCrypt Lua Test Suite"
echo "================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Track test results
TESTS_PASSED=0
TESTS_FAILED=0

# Function to run a test
run_test() {
    local name=$1
    local script=$2
    
    echo -n "Running $name... "
    if cd tests && lua "$script" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ PASSED${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗ FAILED${NC}"
        ((TESTS_FAILED++))
        cd tests && lua "$script" 2>&1 | sed 's/^/  /'
    fi
    cd ..
}

# Run tests
run_test "Test Vectors" "test_vectors.lua"
run_test "Random Generation" "test_random.lua"

# Summary
echo ""
echo "================================"
echo "Test Summary"
echo "================================"
echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Failed: ${RED}$TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}Some tests failed!${NC}"
    exit 1
fi