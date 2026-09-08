FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY natively natively
ENV PYTHONUNBUFFERED=1
CMD ["python", "-m", "natively", "hub", "--port", "8080", "--state", "/data/hub.json", "--principal-pub", "POlQgUnQTG0zV0zyN0jyNS5p/VxdRpva/XRI620mdMI=,URDD4v8gJH8XeONCShkyDR5t5NcMFVm7gMg+ZCNNBrw="]
