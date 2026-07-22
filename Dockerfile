FROM python:3.12-slim

# Εγκατάσταση απαραίτητων συστημικών εργαλείων ασφαλείας και εξαρτήσεων
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    sqlmap \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Ορισμός working directory
WORKDIR /app

# Αντιγραφή του requirements.txt πρώτα για καλύτερο caching
COPY requirements.txt .

# Εγκατάσταση Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Αντιγραφή ολόκληρου του υπόλοιπου codebase
COPY . .

# Ορισμός PYTHONPATH
ENV PYTHONPATH=/app

# Default entrypoint για την εκτέλεση του CLI
ENTRYPOINT ["python3", "cli.py"]