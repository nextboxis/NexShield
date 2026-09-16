FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000

# Install nmap, ping, and network utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
COPY requirements-optional.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Create non-root user and assign permissions
RUN useradd -m -u 1000 -s /bin/bash nexshield \
    && mkdir -p /app/data \
    && chown -R nexshield:nexshield /app

USER nexshield

# Expose Flask default port
EXPOSE 5000

# Healthcheck to ensure web service is healthy
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000').read()" || exit 1

# Run the application
CMD ["python", "run.py", "--host", "0.0.0.0"]
