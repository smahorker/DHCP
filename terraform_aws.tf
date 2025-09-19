# Terraform Configuration for Meraki DHCP Device Classifier on AWS
# Deploy with: terraform init && terraform plan && terraform apply

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

# Variables
variable "aws_region" {
  description = "AWS region to deploy to"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "meraki_api_key" {
  description = "Meraki Dashboard API Key"
  type        = string
  sensitive   = true
}

variable "fingerbank_api_key" {
  description = "Fingerbank API Key"
  type        = string
  sensitive   = true
}

variable "webhook_secret" {
  description = "Webhook shared secret"
  type        = string
  sensitive   = true
}

variable "auto_apply_policies" {
  description = "Whether to automatically apply device policies"
  type        = bool
  default     = false
}

variable "container_image" {
  description = "Container image URI for the application (optional - defaults to ECR repository)"
  type        = string
  default     = null
}

# AWS Provider
provider "aws" {
  region = var.aws_region
}

# Data sources
data "aws_caller_identity" "current" {}

# ECR Repository for container images
resource "aws_ecr_repository" "app" {
  name                 = "meraki-classifier-${var.environment}"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

# ECR Lifecycle Policy
resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 10 images"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["v"]
          countType     = "imageCountMoreThan"
          countNumber   = 10
        }
        action = {
          type = "expire"
        }
      },
      {
        rulePriority = 2
        description  = "Delete untagged images older than 1 day"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 1
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

# No Lambda components needed

# Processing Queue
resource "aws_sqs_queue" "processing_queue" {
  name                      = "meraki-classifier-processing-${var.environment}"
  message_retention_seconds = 1209600  # 14 days
  visibility_timeout_seconds = 300      # 5 minutes
  
  # Dead letter queue configuration
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq.arn
    maxReceiveCount     = 3
  })
  
  tags = {
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

# Dead Letter Queue
resource "aws_sqs_queue" "dlq" {
  name                      = "meraki-classifier-dlq-${var.environment}"
  message_retention_seconds = 1209600  # 14 days
  
  tags = {
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

# No Lambda function needed

# API Gateway
resource "aws_apigatewayv2_api" "webhook_api" {
  name          = "meraki-classifier-api-${var.environment}"
  protocol_type = "HTTP"
  description   = "Meraki DHCP Device Classification Webhook API"
  
  cors_configuration {
    allow_credentials = false
    allow_headers     = ["content-type", "x-amz-date", "authorization", "x-api-key", "x-amz-security-token", "x-meraki-signature"]
    allow_methods     = ["GET", "POST", "OPTIONS"]
    allow_origins     = ["*"]
    expose_headers    = ["date", "x-api-id"]
    max_age          = 300
  }
  
  tags = {
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

# API Gateway Stage
resource "aws_apigatewayv2_stage" "api_stage" {
  api_id      = aws_apigatewayv2_api.webhook_api.id
  name        = var.environment
  auto_deploy = true
  
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_logs.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip            = "$context.identity.sourceIp"
      requestTime   = "$context.requestTime"
      httpMethod    = "$context.httpMethod"
      resourcePath  = "$context.resourcePath"
      status        = "$context.status"
      protocol      = "$context.protocol"
      responseLength = "$context.responseLength"
    })
  }
  
  tags = {
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

# API Gateway Log Group
resource "aws_cloudwatch_log_group" "api_logs" {
  name              = "/aws/apigateway/meraki-classifier-${var.environment}"
  retention_in_days = 7
  
  tags = {
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

# IAM Role for API Gateway to access SQS
resource "aws_iam_role" "api_gateway_sqs_role" {
  name = "meraki-classifier-apigateway-sqs-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "apigateway.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

# IAM Policy for API Gateway to send messages to SQS
resource "aws_iam_role_policy" "api_gateway_sqs_policy" {
  name = "meraki-classifier-apigateway-sqs-policy-${var.environment}"
  role = aws_iam_role.api_gateway_sqs_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sqs:SendMessage"
        ]
        Resource = aws_sqs_queue.processing_queue.arn
      }
    ]
  })
}

# SQS Integration
resource "aws_apigatewayv2_integration" "sqs_integration" {
  api_id             = aws_apigatewayv2_api.webhook_api.id
  integration_type   = "AWS_PROXY"
  integration_subtype = "SQS-SendMessage"
  
  credentials_arn = aws_iam_role.api_gateway_sqs_role.arn
  
  request_parameters = {
    QueueUrl    = aws_sqs_queue.processing_queue.url
    MessageBody = "$request.body"
  }
}

# API Routes
resource "aws_apigatewayv2_route" "webhook_route" {
  api_id    = aws_apigatewayv2_api.webhook_api.id
  route_key = "POST /webhook"
  target    = "integrations/${aws_apigatewayv2_integration.sqs_integration.id}"
}

resource "aws_apigatewayv2_route" "meraki_webhook_route" {
  api_id    = aws_apigatewayv2_api.webhook_api.id
  route_key = "POST /meraki-webhook"
  target    = "integrations/${aws_apigatewayv2_integration.sqs_integration.id}"
}

# No Lambda permission needed

# CloudWatch Alarms for SQS
resource "aws_cloudwatch_metric_alarm" "sqs_high_queue_depth" {
  alarm_name          = "meraki-classifier-high-queue-depth-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "ApproximateNumberOfVisibleMessages"
  namespace           = "AWS/SQS"
  period              = "300"
  statistic           = "Average"
  threshold           = "100"
  alarm_description   = "This metric monitors SQS queue depth"
  
  dimensions = {
    QueueName = aws_sqs_queue.processing_queue.name
  }
  
  tags = {
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

resource "aws_cloudwatch_metric_alarm" "sqs_dlq_messages" {
  alarm_name          = "meraki-classifier-dlq-messages-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "ApproximateNumberOfVisibleMessages"
  namespace           = "AWS/SQS"
  period              = "300"
  statistic           = "Maximum"
  threshold           = "0"
  alarm_description   = "This metric monitors dead letter queue messages"
  
  dimensions = {
    QueueName = aws_sqs_queue.dlq.name
  }
  
  tags = {
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

# Outputs
output "webhook_url" {
  description = "Webhook endpoint URL"
  value       = "https://${aws_apigatewayv2_api.webhook_api.id}.execute-api.${var.aws_region}.amazonaws.com/${var.environment}/webhook"
}

output "health_check_url" {
  description = "Health check endpoint URL"
  value       = "https://${aws_apigatewayv2_api.webhook_api.id}.execute-api.${var.aws_region}.amazonaws.com/${var.environment}/health"
}

output "api_gateway_url" {
  description = "Base API Gateway URL"
  value       = "https://${aws_apigatewayv2_api.webhook_api.id}.execute-api.${var.aws_region}.amazonaws.com/${var.environment}"
}

output "api_gateway_sqs_integration" {
  description = "API Gateway SQS integration status"
  value       = "Direct SQS integration configured"
}

# VPC and Networking for Fargate SQS Workers
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "meraki-classifier-vpc-${var.environment}"
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name        = "meraki-classifier-igw-${var.environment}"
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

# Private Subnets for Fargate SQS Workers
resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index + 10}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name        = "meraki-classifier-private-${count.index + 1}-${var.environment}"
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

# NAT Gateway for private subnets (for internet access - optional with VPC endpoints)
resource "aws_eip" "nat" {
  count  = 0  # Disabled since VPC endpoints handle AWS services
  domain = "vpc"

  tags = {
    Name        = "meraki-classifier-nat-eip-${var.environment}"
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

# Single public subnet for NAT gateway
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name        = "meraki-classifier-public-${var.environment}"
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

resource "aws_nat_gateway" "main" {
  count         = 0  # Disabled since VPC endpoints handle AWS services
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public.id

  tags = {
    Name        = "meraki-classifier-nat-${var.environment}"
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }

  depends_on = [aws_internet_gateway.main]
}

# Route Tables
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name        = "meraki-classifier-public-rt-${var.environment}"
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  # No default route since we use VPC endpoints for AWS services
  # External internet access via Fingerbank API handled through VPC endpoints

  tags = {
    Name        = "meraki-classifier-private-rt-${var.environment}"
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

# Route Table Associations
resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# Data source for availability zones
data "aws_availability_zones" "available" {
  state = "available"
}

# VPC Endpoints for cost optimization (avoid NAT gateway charges)
resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.main.id
  service_name = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids = [aws_route_table.private.id]

  tags = {
    Name        = "meraki-classifier-s3-endpoint-${var.environment}"
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

resource "aws_vpc_endpoint" "ecr_dkr" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ecr.dkr"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = {
    Name        = "meraki-classifier-ecr-dkr-endpoint-${var.environment}"
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ecr.api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = {
    Name        = "meraki-classifier-ecr-api-endpoint-${var.environment}"
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

resource "aws_vpc_endpoint" "logs" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.logs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = {
    Name        = "meraki-classifier-logs-endpoint-${var.environment}"
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

resource "aws_vpc_endpoint" "sqs" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.sqs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = {
    Name        = "meraki-classifier-sqs-endpoint-${var.environment}"
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

# Security Group for VPC Endpoints
resource "aws_security_group" "vpc_endpoints" {
  name_prefix = "meraki-classifier-vpc-endpoints-${var.environment}"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.fargate.id]
  }

  tags = {
    Name        = "meraki-classifier-vpc-endpoints-sg-${var.environment}"
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

# ECS Cluster for Fargate
resource "aws_ecs_cluster" "main" {
  name = "meraki-classifier-${var.environment}"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  
  tags = {
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

# ECS Task Execution Role
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "meraki-classifier-ecs-execution-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

# Attach ECS task execution policy
resource "aws_iam_role_policy_attachment" "ecs_task_execution_role_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# ECS Task Role (for SQS access)
resource "aws_iam_role" "ecs_task_role" {
  name = "meraki-classifier-ecs-task-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

# ECS Task Policy for SQS access
resource "aws_iam_role_policy" "ecs_task_policy" {
  name = "meraki-classifier-ecs-task-policy-${var.environment}"
  role = aws_iam_role.ecs_task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sqs:SendMessage",
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = [
          aws_sqs_queue.processing_queue.arn,
          aws_sqs_queue.dlq.arn
        ]
      }
    ]
  })
}

# Security Group for Fargate SQS Workers
resource "aws_security_group" "fargate" {
  name_prefix = "meraki-classifier-fargate-${var.environment}"
  vpc_id      = aws_vpc.main.id

  # No ingress rules needed for SQS workers
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "meraki-classifier-fargate-sg-${var.environment}"
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

# No ALB needed for SQS worker-only architecture

# No webhook receiver task definition needed

# ECS Task Definition - SQS Worker
resource "aws_ecs_task_definition" "sqs_worker" {
  family                   = "meraki-classifier-worker-${var.environment}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([
    {
      name  = "sqs-worker"
      image = coalesce(var.container_image, "${aws_ecr_repository.app.repository_url}:latest")
      
      # No port mappings needed for SQS worker
      
      environment = [
        {
          name  = "ENVIRONMENT"
          value = var.environment
        },
        {
          name  = "LOG_LEVEL"
          value = "INFO"
        },
        {
          name  = "MERAKI_API_KEY"
          value = var.meraki_api_key
        },
        {
          name  = "FINGERBANK_API_KEY"
          value = var.fingerbank_api_key
        },
        {
          name  = "WEBHOOK_SECRET"
          value = var.webhook_secret
        },
        {
          name  = "AUTO_APPLY_POLICIES"
          value = var.auto_apply_policies ? "true" : "false"
        },
        {
          name  = "ENABLE_CONFLICT_RESOLUTION"
          value = "true"
        },
        {
          name  = "ENABLE_USAGE_ANALYSIS"
          value = "true"
        },
        {
          name  = "BATCH_SIZE"
          value = "100"
        },
        {
          name  = "SQS_PROCESSING_QUEUE_URL"
          value = aws_sqs_queue.processing_queue.url
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = "/ecs/meraki-classifier-worker-${var.environment}"
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }
      
      # No health check needed for SQS worker
    }
  ])

  tags = {
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

# CloudWatch Log Group for SQS Worker
resource "aws_cloudwatch_log_group" "worker_logs" {
  name              = "/ecs/meraki-classifier-worker-${var.environment}"
  retention_in_days = 14

  tags = {
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

# No webhook receiver service needed

# ECS Service - SQS Worker
resource "aws_ecs_service" "sqs_worker" {
  name            = "sqs-worker-${var.environment}"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.sqs_worker.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.fargate.id]
    assign_public_ip = false
  }

  tags = {
    Environment = var.environment
    Project     = "meraki-device-classifier"
  }
}

output "processing_queue_url" {
  description = "Processing queue URL"
  value       = aws_sqs_queue.processing_queue.url
}

output "dead_letter_queue_url" {
  description = "Dead letter queue URL"
  value       = aws_sqs_queue.dlq.url
}

output "ecs_cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.main.name
}

output "sqs_worker_service_name" {
  description = "SQS worker service name"
  value       = aws_ecs_service.sqs_worker.name
}

output "ecr_repository_url" {
  description = "ECR repository URL for container images"
  value       = aws_ecr_repository.app.repository_url
}

output "ecr_repository_name" {
  description = "ECR repository name"
  value       = aws_ecr_repository.app.name
}