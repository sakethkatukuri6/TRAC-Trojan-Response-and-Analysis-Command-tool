FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy and install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy platform source tree
COPY . .

# Expose M7 API (8000) and M8 Command Console (8088)
EXPOSE 8000 8088

# Default to running the unified analyst console
CMD ["python", "-m", "m8_ui_devops.cli", "--serve-ui", "--host", "0.0.0.0", "--port", "8088"]
