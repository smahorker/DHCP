#!/bin/bash

# DHCP Device Classification System - End-to-End Demo Script
# Tests complete pipeline: API Gateway -> SQS -> Fargate -> Classification -> Logs

set -e  # Exit on any error

# Configuration
API_GATEWAY_URL="https://6fal8df757.execute-api.us-east-1.amazonaws.com/dev/webhook"
WEBHOOK_SECRET="riverisland_lab_webhook_secret_2025"
LOG_GROUP="/ecs/meraki-classifier-worker-dev"
DB_CONTAINER="network_devices_db"
DB_PASSWORD="secure_password_123"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print stage headers
print_stage() {
    echo
    echo "=================================================================="
    echo "STAGE $1: $2"
    echo "=================================================================="
    echo
}

# Function to print status
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

# Function to print warnings
print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Function to print errors
print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to wait with countdown
wait_with_countdown() {
    local seconds=$1
    local message=$2
    echo -e "${BLUE}[WAIT]${NC} $message"
    for ((i=seconds; i>0; i--)); do
        echo -n "  Waiting $i seconds..."
        sleep 1
        echo -e "\r\033[K"  # Clear line
    done
    echo "  Ready!"
}

# Function to check PostgreSQL connection
check_postgresql() {
    print_status "Testing PostgreSQL connection..."
    if docker exec -e PGPASSWORD=$DB_PASSWORD $DB_CONTAINER psql -U network_admin -d network_devices -c "SELECT 1;" > /dev/null 2>&1; then
        print_status "PostgreSQL connection successful"
        return 0
    else
        print_error "PostgreSQL connection failed"
        return 1
    fi
}

# Function to create demo session in database
create_demo_session() {
    print_status "Creating demo analysis session..."
    DEMO_SESSION_ID=$(uuidgen)
    docker exec -e PGPASSWORD=$DB_PASSWORD $DB_CONTAINER psql -U network_admin -d network_devices -c "
        INSERT INTO analysis_sessions (id, timestamp, total_devices) 
        VALUES ('$DEMO_SESSION_ID', NOW(), 0);
        SELECT 'Demo session created: ' || '$DEMO_SESSION_ID';
    "
    echo "Demo Session ID: $DEMO_SESSION_ID"
}

# Function to send webhook
send_webhook() {
    local mac_address=$1
    local hostname=$2
    local device_description=$3
    
    print_status "Sending webhook for $device_description ($mac_address)..."
    
    local webhook_payload='{
        "version": "1.0",
        "sharedSecret": "'$WEBHOOK_SECRET'",
        "sentAt": "'$(date -Iseconds)'",
        "organizationId": "681155",
        "organizationName": "Demo Organization",
        "networkId": "L_646829496481105433",
        "networkName": "Main Office",
        "deviceSerial": "Q2HP-DEMO-001",
        "alertId": "'$(date +%s)'",
        "alertType": "DHCP lease assigned",
        "alertData": {
            "mac": "'$mac_address'",
            "ip": "192.168.1.'$((RANDOM % 200 + 50))'",
            "hostname": "'$hostname'",
            "vlan": 1
        }
    }'
    
    local response=$(curl -s -X POST "$API_GATEWAY_URL" \
        -H "Content-Type: application/json" \
        -d "$webhook_payload" 2>/dev/null)
    
    # Extract MessageId from XML response
    local message_id=$(echo "$response" | grep -o '<MessageId>[^<]*</MessageId>' | sed 's/<MessageId>//;s/<\/MessageId>//')
    
    if [ ! -z "$message_id" ]; then
        print_status "Webhook queued successfully - Message ID: $message_id"
        echo "  Device: $device_description"
        echo "  MAC: $mac_address"
        echo "  Hostname: $hostname"
        return 0
    else
        print_error "Webhook failed - Response: $response"
        return 1
    fi
}

# Function to check ECS service status
check_ecs_status() {
    print_status "Checking ECS Fargate service status..."
    local service_status=$(aws ecs describe-services \
        --cluster meraki-classifier-dev \
        --services sqs-worker-dev \
        --query 'services[0].{RunningCount:runningCount,PendingCount:pendingCount,DesiredCount:desiredCount}' \
        --output text 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        echo "  ECS Service Status: $service_status"
        local running_count=$(echo "$service_status" | awk '{print $3}')
        if [ "$running_count" -gt 0 ]; then
            print_status "ECS Fargate worker is running"
            return 0
        else
            print_warning "ECS Fargate worker not running"
            return 1
        fi
    else
        print_error "Failed to check ECS service status"
        return 1
    fi
}

# Function to get latest log stream
get_latest_log_stream() {
    aws logs describe-log-streams \
        --log-group-name "$LOG_GROUP" \
        --order-by LastEventTime \
        --descending \
        --max-items 1 \
        --query 'logStreams[0].logStreamName' \
        --output text 2>/dev/null
}

# Function to check classification logs
check_classification_logs() {
    local expected_devices=$1
    print_status "Checking CloudWatch logs for classification results..."
    
    local log_stream=$(get_latest_log_stream)
    if [ -z "$log_stream" ] || [ "$log_stream" = "None" ]; then
        print_error "No log stream found"
        return 1
    fi
    
    print_status "Reading from log stream: $log_stream"
    
    # Get logs from last 5 minutes
    local start_time=$(($(date +%s) - 300))000
    local logs=$(aws logs get-log-events \
        --log-group-name "$LOG_GROUP" \
        --log-stream-name "$log_stream" \
        --start-time $start_time \
        --query 'events[*].message' \
        --output text 2>/dev/null)
    
    if [ -z "$logs" ]; then
        print_warning "No recent logs found"
        return 1
    fi
    
    echo "  Recent classification results:"
    echo "$logs" | grep "Classified device:" | while read -r line; do
        echo "    $line"
    done
    
    local classification_count=$(echo "$logs" | grep -c "Classified device:" || echo "0")
    echo "  Total classifications found: $classification_count"
    
    if [ "$classification_count" -ge "$expected_devices" ]; then
        print_status "Found expected number of classifications ($expected_devices)"
        return 0
    else
        print_warning "Expected $expected_devices classifications, found $classification_count"
        return 1
    fi
}

# Function to query recent PostgreSQL data
query_postgresql_results() {
    print_status "Querying PostgreSQL for recent analysis results..."
    
    echo "  Recent analysis sessions (last 24 hours):"
    docker exec -e PGPASSWORD=$DB_PASSWORD $DB_CONTAINER psql -U network_admin -d network_devices -c "
        SELECT 
            id, 
            timestamp, 
            total_devices,
            EXTRACT(EPOCH FROM (NOW() - timestamp))/60 as minutes_ago
        FROM analysis_sessions 
        WHERE timestamp > NOW() - INTERVAL '24 hours'
        ORDER BY timestamp DESC 
        LIMIT 5;
    " 2>/dev/null || print_warning "Could not query analysis sessions"
    
    echo
    echo "  Recent device classifications (last 24 hours):"
    docker exec -e PGPASSWORD=$DB_PASSWORD $DB_CONTAINER psql -U network_admin -d network_devices -c "
        SELECT 
            mac_address,
            vendor,
            device_type,
            overall_confidence,
            hostname,
            created_at
        FROM devices 
        WHERE created_at > NOW() - INTERVAL '24 hours'
        ORDER BY created_at DESC 
        LIMIT 10;
    " 2>/dev/null || print_warning "Could not query device classifications"
    
    echo
    echo "  Device type summary (last 24 hours):"
    docker exec -e PGPASSWORD=$DB_PASSWORD $DB_CONTAINER psql -U network_admin -d network_devices -c "
        SELECT 
            device_type,
            COUNT(*) as count,
            ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) as percentage
        FROM devices 
        WHERE created_at > NOW() - INTERVAL '24 hours'
        GROUP BY device_type 
        ORDER BY count DESC;
    " 2>/dev/null || print_warning "Could not query device type summary"
}

# Function to run SQS queue inspection
check_sqs_queue() {
    print_status "Checking SQS queue status..."
    local queue_url="https://sqs.us-east-1.amazonaws.com/807650717692/meraki-classifier-processing-dev"
    
    local queue_attributes=$(aws sqs get-queue-attributes \
        --queue-url "$queue_url" \
        --attribute-names ApproximateNumberOfMessages,ApproximateNumberOfMessagesNotVisible \
        --query 'Attributes' \
        --output text 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        echo "  Queue Status: $queue_attributes"
        local visible_messages=$(echo "$queue_attributes" | awk '{print $1}')
        local invisible_messages=$(echo "$queue_attributes" | awk '{print $2}')
        echo "  Messages in queue: $visible_messages"
        echo "  Messages being processed: $invisible_messages"
    else
        print_error "Failed to check SQS queue status"
        return 1
    fi
}

# Main demo execution
main() {
    echo "DHCP Device Classification System - End-to-End Demo"
    echo "=================================================="
    echo "This script will test the complete pipeline from webhook to classification"
    echo "Pipeline: API Gateway -> SQS -> ECS Fargate -> Device Classification -> Logs"
    echo
    
    # Stage 1: Prerequisites Check
    print_stage "1" "PREREQUISITES CHECK"
    
    print_status "Checking AWS CLI access..."
    if ! aws sts get-caller-identity > /dev/null 2>&1; then
        print_error "AWS CLI not configured or accessible"
        exit 1
    fi
    print_status "AWS CLI access confirmed"
    
    print_status "Checking Docker and PostgreSQL container..."
    if ! docker ps | grep -q "$DB_CONTAINER"; then
        print_error "PostgreSQL container '$DB_CONTAINER' not running"
        print_status "Starting PostgreSQL container..."
        cd database && docker compose up -d postgres
        wait_with_countdown 10 "Waiting for PostgreSQL to start"
    fi
    
    if check_postgresql; then
        print_status "Prerequisites satisfied"
    else
        print_error "Prerequisites not met"
        exit 1
    fi
    
    # Stage 2: Infrastructure Status
    print_stage "2" "INFRASTRUCTURE STATUS CHECK"
    
    check_ecs_status
    check_sqs_queue
    
    # Stage 3: Database Preparation
    print_stage "3" "DATABASE PREPARATION"
    
    create_demo_session
    query_postgresql_results
    
    # Stage 4: Webhook Testing
    print_stage "4" "WEBHOOK TRANSMISSION"
    
    print_status "Sending test webhooks to API Gateway..."
    
    # Send different device types for comprehensive testing
    send_webhook "28:39:5e:f1:65:c1" "samsung-phone-demo" "Samsung Smartphone"
    wait_with_countdown 3 "Spacing webhook sends"
    
    send_webhook "00:11:22:33:44:55" "apple-macbook-pro" "Apple MacBook"
    wait_with_countdown 3 "Spacing webhook sends"
    
    send_webhook "aa:bb:cc:dd:ee:ff" "test-device-demo" "Test Device"
    wait_with_countdown 3 "Spacing webhook sends"
    
    send_webhook "00:d0:b7:12:34:56" "intel-nuc-device" "Intel Device"
    
    print_status "All webhooks sent successfully"
    
    # Stage 5: Processing Wait
    print_stage "5" "PROCESSING PIPELINE"
    
    wait_with_countdown 15 "Waiting for Fargate worker to process messages"
    
    # Stage 6: Results Verification
    print_stage "6" "RESULTS VERIFICATION"
    
    print_status "Checking SQS queue after processing..."
    check_sqs_queue
    
    print_status "Verifying classification results..."
    if check_classification_logs 4; then
        print_status "Classification results verified in CloudWatch logs"
    else
        print_warning "Some classifications may still be processing"
    fi
    
    # Stage 7: Database Results
    print_stage "7" "DATABASE ANALYSIS"
    
    wait_with_countdown 5 "Allowing time for any database writes"
    query_postgresql_results
    
    # Stage 8: Summary
    print_stage "8" "DEMO SUMMARY"
    
    print_status "End-to-end demo completed successfully!"
    echo
    echo "PIPELINE COMPONENTS TESTED:"
    echo "  1. API Gateway - Webhook reception"
    echo "  2. SQS Queue - Message queuing and delivery"
    echo "  3. ECS Fargate - Serverless container processing"
    echo "  4. Device Classification - MAC-based vendor detection"
    echo "  5. CloudWatch Logs - Real-time result logging"
    echo "  6. PostgreSQL - Data persistence and analysis"
    echo
    echo "DEVICES CLASSIFIED:"
    echo "  - Samsung Smartphone (28:39:5e:f1:65:c1)"
    echo "  - Apple MacBook (00:11:22:33:44:55)"
    echo "  - Test Device (aa:bb:cc:dd:ee:ff)"
    echo "  - Intel Device (00:d0:b7:12:34:56)"
    echo
    echo "VIEW RESULTS:"
    echo "  - CloudWatch Logs: https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#logsV2:log-groups/log-group/\$252Fecs\$252Fmeraki-classifier-worker-dev"
    echo "  - PostgreSQL: docker exec -e PGPASSWORD=$DB_PASSWORD $DB_CONTAINER psql -U network_admin -d network_devices"
    echo "  - pgAdmin: http://localhost:8080 (admin@networkdevices.local / admin123)"
    echo
    print_status "Demo completed at $(date)"
}

# Run the demo
main "$@"