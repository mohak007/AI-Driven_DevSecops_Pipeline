FROM python:3.12-slim

#Metadata for traceability
LABEL maintainer="mohak.kumar53@gmail.com"
LABEL project="ai-devsecops"
LABEL phase="1"

#System deps
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

#Create a non root user 
RUN useradd --create-home appuser

WORKDIR /app

#Install python deps before copying code
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

#Copy application code
COPY app.py .

#Switch to non-root user
USER appuser

#Expose only the port app listens on
EXPOSE 5000

#Health Check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD curl -f http://localhost:5000/health || exit 1

# Start with gunicorn: 2 workers × (2×CPU+1) is the standard formula
# For a 1-vCPU machine that's 3 workers; adjust --workers for your instance
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "60", "app:app"]
