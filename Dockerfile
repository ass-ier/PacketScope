FROM node:22-bookworm-slim AS frontend
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PACKETSCOPE_DEMO=true \
    PACKETSCOPE_EXTERNAL_ENABLED=false \
    PACKETSCOPE_DATA=/app/demo-data \
    PACKETSCOPE_BIND=0.0.0.0 \
    PORT=10000
WORKDIR /app
COPY backend/requirements/ ./backend/requirements/
RUN python -m pip install --no-cache-dir --upgrade pip==26.2.1 \
    && python -m pip install --no-cache-dir -r backend/requirements/base.txt -c backend/requirements/lock.txt \
    && useradd --create-home --uid 10001 packetscope \
    && mkdir /app/demo-data \
    && chown packetscope:packetscope /app/demo-data
COPY backend/ ./backend/
COPY fixtures/ ./fixtures/
COPY detection-rules/ ./detection-rules/
COPY --from=frontend /build/frontend/dist/ ./frontend/dist/
USER packetscope
WORKDIR /app/backend
EXPOSE 10000
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
    CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.environ['PORT']+'/api/health',timeout=4)"
CMD ["python", "demo.py"]
