# --- Apache Agent Dockerfile ---
FROM python:3.11-slim

# Metadata
LABEL maintainer="you@example.com"
LABEL description="Lightweight Apache config scanner agent (read-only)"

# Copy script vào container
WORKDIR /agent
COPY apache_agent.py /agent/apache_agent.py

# Chạy mặc định
CMD ["python3", "/agent/apache_agent.py"]
