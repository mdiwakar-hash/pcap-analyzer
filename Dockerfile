FROM python:3.12-slim

# Install tshark (non-interactive to skip license prompt)
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get install -y --no-install-recommends tshark && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Listen on all interfaces so Docker port mapping works
ENV PCAP_HOST=0.0.0.0

EXPOSE 8000

CMD ["python3", "server.py"]
