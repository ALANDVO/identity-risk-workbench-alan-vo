FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/backend
WORKDIR /app
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt && useradd --uid 10001 --create-home app && mkdir /data && chown app:app /data
COPY backend /app/backend
USER 10001
EXPOSE 8000
CMD ["uvicorn","app.main:create_app","--factory","--host","0.0.0.0","--port","8000","--no-proxy-headers"]
