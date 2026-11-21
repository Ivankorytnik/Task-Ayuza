FROM python:3.13-slim
WORKDIR /app
COPY requirements-m01.txt .
RUN pip install --no-cache-dir -r requirements-m01.txt
COPY backend backend
COPY migrations migrations
COPY scripts scripts
COPY alembic.ini .
