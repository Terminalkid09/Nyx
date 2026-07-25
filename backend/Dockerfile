FROM python:3.12-slim AS base

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ cmake libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN playwright install chromium --with-deps || true

COPY backend/ .

# Build C++ native module (optional, skips gracefully)
COPY native ./native
RUN cd native && (pip install pybind11 --break-system-packages 2>/dev/null; \
    cmake -B build -DCMAKE_BUILD_TYPE=Release 2>/dev/null; \
    cmake --build build --parallel 4 2>/dev/null; \
    cp build/nyx_grpc_parser*.so /app/ 2>/dev/null) || true

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
