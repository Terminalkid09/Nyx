FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN playwright install chromium --with-deps 2>&1 || echo "[WARN] playwright install failed — crawler will be unavailable"

COPY backend/ .

EXPOSE 8000 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
