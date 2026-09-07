FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY natively natively
ENV PYTHONUNBUFFERED=1
CMD ["python", "-m", "natively", "hub", "--port", "8080", "--state", "/data/hub.json"]
