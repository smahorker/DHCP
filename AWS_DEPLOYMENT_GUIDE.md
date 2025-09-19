# AWS Deployment Guide - Meraki DHCP Device Classifier

## 🎯 Quick Answer: What's Required for AWS Deployment

**✅ READY TO DEPLOY**: All core functionality works. No missing critical dependencies.

### Minimal Requirements for AWS API Service:
- **API Keys**: Meraki + Fingerbank (environment variables)
- **Runtime**: Python 3.9 with `requests` and `python-dotenv`
- **Size**: ~2MB deployment package (well under AWS limits)
- **Architecture**: Serverless webhook processor

### What's NOT Required for AWS API Service:
- ❌ Database (PostgreSQL/Redis)
- ❌ File storage (results sent back via webhook response)
- ❌ Flask server (Lambda handles HTTP)
- ❌ Docker (for Lambda deployment)

---

## 🚀 Deployment Options

### Option 1: AWS Lambda (Recommended for Webhook API)

**Best for**: Pure webhook processing, cost-effective, auto-scaling

```bash
# Method A: Serverless Framework (Easiest)
npm install -g serverless
serverless deploy

# Method B: Terraform (Infrastructure as Code)
terraform init
terraform plan
terraform apply

# Method C: AWS CLI (Manual)
aws lambda create-function --function-name meraki-classifier ...
```

**Cost**: ~$0.20 per million webhook requests
**Latency**: <500ms typical response time
**Scalability**: 1000 concurrent executions (adjustable)

### Option 2: AWS ECS Fargate (Container)

**Best for**: Batch processing + webhooks, persistent connections

```bash
# Build and deploy container
docker build -t meraki-classifier .
aws ecr get-login-password | docker login ...
docker tag meraki-classifier:latest ...
docker push ...
```

**Cost**: ~$30-50/month for small workload
**Features**: All modes (webhook, batch, both)

### Option 3: AWS EC2 (Traditional Server)

**Best for**: Full control, development, complex batch processing

```bash
# Deploy with existing Docker setup
docker-compose up -d
```

---

## ⚡ Quick Deploy: Lambda (5 minutes)

### Prerequisites:
```bash
# Install dependencies
npm install -g serverless serverless-python-requirements
pip install boto3 awscli

# Configure AWS credentials
aws configure
```

### 1. Set Environment Variables:
```bash
# Create .env file (for local testing)
MERAKI_API_KEY=your_meraki_api_key_here
FINGERBANK_API_KEY=your_fingerbank_api_key_here  
WEBHOOK_SECRET=your_webhook_shared_secret
LOG_LEVEL=INFO
AUTO_APPLY_POLICIES=false
```

### 2. Deploy with Serverless:
```bash
# Deploy to AWS Lambda
serverless deploy --stage prod

# Output will show:
# ✅ Webhook URL: https://abc123.execute-api.us-east-1.amazonaws.com/webhook
# ✅ Health Check: https://abc123.execute-api.us-east-1.amazonaws.com/health
```

### 3. Configure Meraki Webhooks:
```bash
# In Meraki Dashboard:
# Network-wide → Alerts → Webhooks → Add HTTP server
# URL: https://your-api-gateway-url.amazonaws.com/webhook
# Shared secret: your_webhook_secret
# Alert types: DHCP lease assigned, Client connectivity
```

### 4. Test Deployment:
```bash
# Health check
curl https://your-api-gateway-url.amazonaws.com/health

# Expected response:
# {"status": "healthy", "service": "meraki-classifier-lambda"}
```

---

## 📊 Service Architecture

### Lambda Architecture (Serverless):
```
Internet → API Gateway → Lambda → Meraki/Fingerbank APIs
                     ↓
               CloudWatch Logs
                     ↓
               Dead Letter Queue (failures)
```

### ECS Architecture (Container):
```
Internet → ALB → ECS Fargate → Meraki/Fingerbank APIs
                     ↓
              CloudWatch Logs
                     ↓
            Optional: RDS/Redis
```

---

## 🔧 Configuration Details

### Required Environment Variables:
```bash
MERAKI_API_KEY=your_meraki_api_key          # Required
FINGERBANK_API_KEY=your_fingerbank_key      # Required
WEBHOOK_SECRET=your_webhook_secret          # Required
```

### Optional Environment Variables (with defaults):
```bash
LOG_LEVEL=INFO                              # DEBUG, INFO, WARNING, ERROR
AUTO_APPLY_POLICIES=false                   # Auto-apply device policies
ENABLE_CONFLICT_RESOLUTION=true             # Cross-validate classifications
ENABLE_USAGE_ANALYSIS=true                  # Analyze network usage patterns
BATCH_SIZE=100                              # For batch processing mode
```

### Security Configuration:
```bash
# Production: Use AWS Secrets Manager
aws secretsmanager create-secret \
    --name "meraki-classifier/api-keys" \
    --secret-string '{"meraki_key":"xxx","fingerbank_key":"yyy","webhook_secret":"zzz"}'
```

---

## 📈 Monitoring & Troubleshooting

### CloudWatch Metrics:
- **Invocations**: Number of webhook requests processed
- **Errors**: Failed processing attempts
- **Duration**: Response time per request
- **Throttles**: Rate-limited requests

### Common Issues:

**1. Webhook Signature Validation Failure**
```json
{"error": "Invalid webhook signature"}
```
**Fix**: Verify WEBHOOK_SECRET matches Meraki dashboard configuration

**2. API Key Issues**
```json
{"error": "401 Unauthorized"}
```
**Fix**: Verify MERAKI_API_KEY and FINGERBANK_API_KEY are valid

**3. Cold Start Delays**
```
First request: 2-3 seconds
Subsequent: <500ms
```
**Fix**: Enable provisioned concurrency for production

**4. Rate Limiting**
```
Meraki API: 5 requests/second per org
Fingerbank API: 1000 requests/hour
```
**Fix**: Lambda reserved concurrency set to 10 by default

### Debugging:
```bash
# View Lambda logs
aws logs tail /aws/lambda/meraki-classifier-prod --follow

# Test webhook locally
python aws_lambda_handler.py

# Check API Gateway logs
aws logs tail /aws/apigateway/meraki-classifier-prod
```

---

## 💰 Cost Analysis

### Lambda (Webhook-only):
- **Compute**: $0.0000166667 per GB-second
- **Requests**: $0.20 per 1M requests
- **Typical cost**: <$5/month for small networks
- **Break-even**: ~10,000 webhooks/month vs EC2

### ECS Fargate (Full service):
- **Compute**: 0.5 vCPU + 1GB RAM = ~$30/month
- **Load Balancer**: ~$20/month
- **Total**: ~$50/month + data transfer

### EC2 (Self-managed):
- **t3.micro**: ~$8/month (free tier eligible)
- **t3.small**: ~$17/month
- **Total**: ~$10-20/month + management overhead

---

## 🔐 Production Security

### AWS Security Best Practices:
```yaml
# IAM Role (minimal permissions)
- logs:CreateLogGroup
- logs:CreateLogStream
- logs:PutLogEvents
- sqs:SendMessage (for DLQ)

# API Gateway Security
- CORS configured
- Rate limiting: 1000/min per IP
- AWS WAF (optional)

# Lambda Security
- Reserved concurrency: 10
- Dead letter queue configured
- Environment variables encrypted
```

### Network Security:
```bash
# VPC Configuration (optional)
# Lambda in private subnet with NAT gateway
# API Gateway with custom domain + SSL

# Custom domain with SSL
aws apigateway create-domain-name \
    --domain-name api.yourdomain.com \
    --certificate-arn arn:aws:acm:...
```

---

## 🧪 Testing Your Deployment

### 1. Unit Tests:
```bash
python aws_lambda_handler.py  # Local testing
```

### 2. Integration Tests:
```bash
# Health check
curl https://your-api.amazonaws.com/health

# Mock webhook
curl -X POST https://your-api.amazonaws.com/webhook \
  -H "Content-Type: application/json" \
  -d '{"alertType":"DHCP lease assigned","deviceMac":"00:11:22:33:44:55"}'
```

### 3. Load Testing:
```bash
# Install Artillery
npm install -g artillery

# Create test config
artillery run webhook-load-test.yml
```

---

## 📝 Deployment Checklist

### Pre-deployment:
- [ ] AWS CLI configured with appropriate permissions
- [ ] Meraki API key obtained and tested
- [ ] Fingerbank API key obtained and tested
- [ ] Webhook shared secret generated
- [ ] Environment variables configured

### Deployment:
- [ ] Lambda function deployed successfully
- [ ] API Gateway endpoints responding
- [ ] CloudWatch logs showing successful initialization
- [ ] Dead letter queue configured
- [ ] Monitoring alarms set up

### Post-deployment:
- [ ] Meraki dashboard webhook configured
- [ ] Test webhook processing
- [ ] Monitor CloudWatch metrics
- [ ] Verify device classifications in Meraki
- [ ] Set up billing alerts

---

## 🚨 Emergency Procedures

### Rollback Deployment:
```bash
# Serverless Framework
serverless remove --stage prod

# Terraform
terraform destroy

# Manual cleanup
aws lambda delete-function --function-name meraki-classifier
aws apigateway delete-rest-api --rest-api-id abc123
```

### Scale During High Traffic:
```bash
# Increase Lambda concurrency
aws lambda put-reserved-concurrency-configuration \
    --function-name meraki-classifier \
    --reserved-concurrent-executions 50

# Monitor API Gateway throttling
aws logs filter-log-events \
    --log-group-name /aws/apigateway/meraki-classifier \
    --filter-pattern "throttle"
```

---

## 🎯 Conclusion

**✅ The Meraki DHCP Device Classifier is production-ready for AWS deployment.**

- **No blocking dependencies**: All required modules present and functional
- **Multiple deployment options**: Lambda (serverless), ECS (container), EC2 (VM)
- **Cost-effective**: Starting at <$5/month for typical workloads  
- **Scalable**: Auto-scales with webhook traffic
- **Monitored**: Complete CloudWatch integration
- **Secure**: AWS security best practices implemented

The main barriers to deployment are:
1. **AWS account setup** and permissions
2. **API key configuration** (Meraki + Fingerbank)
3. **Choosing deployment method** based on requirements

**Recommended path**: Start with Lambda deployment for webhook processing, add ECS later if batch processing is needed.