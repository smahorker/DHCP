FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies (removed curl since no health check needed)
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Add SQS worker dependencies (removed Flask/gunicorn)
RUN pip install --no-cache-dir \
    python-dotenv==1.0.0 \
    boto3==1.26.137

# Copy source code
COPY src/ ./src/
COPY *.py ./

# Create logs directory
RUN mkdir -p /app/logs

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash app && \
    chown -R app:app /app
USER app

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# No port exposure needed for SQS worker

# No health check needed for SQS worker (ECS handles task health)

# Run SQS worker
CMD ["python", "fargate_app.py"]