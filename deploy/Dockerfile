FROM python:3.10-slim

WORKDIR /app

# Install nmap and other system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Expose Flask default port
EXPOSE 5000

# Run the application
CMD ["python", "run.py"]
