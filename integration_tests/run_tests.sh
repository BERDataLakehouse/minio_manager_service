#!/usr/bin/env bash
# Integration Test Runner
# Runs test groups with fresh Docker environment between each group.
#
# Usage:
#   ./run_tests.sh           # Run all test groups
#   ./run_tests.sh management # Run only management tests
#   ./run_tests.sh sharing    # Run only sharing tests
#   ./run_tests.sh workspaces # Run only workspaces tests

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Track results (simple approach for bash 3.x compatibility)
SUMMARY_FILE=$(mktemp)
OVERALL_START_TIME=0

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

format_duration() {
    local seconds=$1
    local minutes=$((seconds / 60))
    local secs=$((seconds % 60))
    
    if [ $minutes -gt 0 ]; then
        echo "${minutes}m ${secs}s"
    else
        echo "${secs}s"
    fi
}

restart_docker() {
    log_info "Restarting Docker containers..."
    cd "$PROJECT_ROOT"
    docker compose down --remove-orphans 2>/dev/null || true
    docker compose up -d --build
    
    log_info "Waiting for services to be ready..."
    sleep 10
    
    # Run prerequisites to ensure test users exist
    log_info "Setting up test prerequisites..."
    cd "$SCRIPT_DIR"
    python ensure_test_prerequisites.py
    
    log_info "Docker containers ready!"
}

run_tests() {
    local test_group=$1
    local test_path="tests/${test_group}/"
    
    log_info "========================================="
    log_info "Running tests: ${test_group}"
    log_info "========================================="
    
    cd "$SCRIPT_DIR"
    
    # Track timing
    local start_time=$(date +%s)
    
    # Run pytest and capture output to parse results
    local output
    local exit_code=0
    
    # Run parallel-safe tests first, then serial tests sequentially
    local parallel_output serial_output
    local parallel_exit=0 serial_exit=0

    parallel_output=$(pytest "${test_path}" -m "not serial" -n auto -v --tb=short 2>&1) || parallel_exit=$?
    serial_output=$(pytest "${test_path}" -m "serial" -v --tb=short 2>&1) || serial_exit=$?

    output="${parallel_output}
${serial_output}"
    # Exit code 5 = no tests collected (e.g. no serial tests in this group) — not a failure
    if { [ $parallel_exit -ne 0 ] && [ $parallel_exit -ne 5 ]; } || \
       { [ $serial_exit -ne 0 ] && [ $serial_exit -ne 5 ]; }; then
        exit_code=1
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    echo "$output"
    
    # Extract and sum counts from pytest output (parallel + serial runs)
    local passed=0 failed=0 skipped=0
    for val in $(echo "$output" | grep -oE "[0-9]+ passed" | grep -oE "[0-9]+"); do
        passed=$((passed + val))
    done
    for val in $(echo "$output" | grep -oE "[0-9]+ failed" | grep -oE "[0-9]+"); do
        failed=$((failed + val))
    done
    for val in $(echo "$output" | grep -oE "[0-9]+ skipped" | grep -oE "[0-9]+"); do
        skipped=$((skipped + val))
    done
    
    local status="PASSED"
    if [ $exit_code -ne 0 ]; then
        status="FAILED"
    fi
    
    # Store result in temp file (group|status|passed|failed|skipped|duration)
    echo "${test_group}|${status}|${passed}|${failed}|${skipped}|${duration}" >> "$SUMMARY_FILE"
    
    if [ $exit_code -eq 0 ]; then
        log_info "✅ ${test_group} tests PASSED ($(format_duration $duration))"
        return 0
    else
        log_error "❌ ${test_group} tests FAILED ($(format_duration $duration))"
        return 1
    fi
}

run_test_group() {
    local group=$1
    restart_docker
    run_tests "$group" || true  # Don't exit on failure, continue to summary
}

print_summary() {
    local overall_end_time=$(date +%s)
    local overall_duration=$((overall_end_time - OVERALL_START_TIME))
    
    echo ""
    echo -e "${BOLD}=========================================${NC}"
    echo -e "${BOLD}           TEST RESULTS SUMMARY          ${NC}"
    echo -e "${BOLD}=========================================${NC}"
    echo ""
    
    printf "%-15s %-10s %-8s %-8s %-8s %-10s\n" "GROUP" "STATUS" "PASSED" "FAILED" "SKIPPED" "TIME"
    echo "-------------------------------------------------------------------"
    
    local total_passed=0
    local total_failed=0
    local total_skipped=0
    local any_failed=0
    
    # Read results from temp file
    while IFS='|' read -r group status passed failed skipped duration; do
        local time_str=$(format_duration $duration)
        
        total_passed=$((total_passed + passed))
        total_failed=$((total_failed + failed))
        total_skipped=$((total_skipped + skipped))
        
        if [ "$status" == "PASSED" ]; then
            printf "%-15s ${GREEN}%-10s${NC} %-8s %-8s %-8s %-10s\n" "$group" "✅ PASS" "$passed" "$failed" "$skipped" "$time_str"
        else
            printf "%-15s ${RED}%-10s${NC} %-8s %-8s %-8s %-10s\n" "$group" "❌ FAIL" "$passed" "$failed" "$skipped" "$time_str"
            any_failed=1
        fi
    done < "$SUMMARY_FILE"
    
    echo "-------------------------------------------------------------------"
    printf "%-15s %-10s %-8s %-8s %-8s %-10s\n" "TOTAL" "" "$total_passed" "$total_failed" "$total_skipped" "$(format_duration $overall_duration)"
    echo ""
    
    # Cleanup temp file
    rm -f "$SUMMARY_FILE"
    
    if [ $any_failed -eq 0 ]; then
        echo -e "${GREEN}${BOLD}✅ ALL TEST GROUPS PASSED!${NC}"
        return 0
    else
        echo -e "${RED}${BOLD}❌ SOME TEST GROUPS FAILED${NC}"
        return 1
    fi
}

# Main execution
main() {
    local target="${1:-all}"
    
    OVERALL_START_TIME=$(date +%s)
    
    # Clear any previous results
    > "$SUMMARY_FILE"
    
    log_info "Starting integration test run..."
    log_info "Target: ${target}"
    
    case "$target" in
        management)
            run_test_group "management"
            ;;
        sharing)
            run_test_group "sharing"
            ;;
        workspaces)
            run_test_group "workspaces"
            ;;
        security)
            run_test_group "security"
            ;;
        locking)
            run_test_group "locking"
            ;;
        polaris)
            run_test_group "management" "tests/management/test_polaris.py"
            ;;
        all)
            run_test_group "management"
            run_test_group "sharing"
            run_test_group "workspaces"
            run_test_group "security"
            run_test_group "locking"
            ;;
        *)
            log_error "Unknown test group: ${target}"
            echo "Available groups: management, sharing, workspaces, security, locking, polaris, all"
            exit 1
            ;;
    esac
    
    # Print summary and exit with appropriate code
    if print_summary; then
        exit 0
    else
        exit 1
    fi
}

main "$@"
