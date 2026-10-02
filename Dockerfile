FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/srv \
    AUDIT_HOST=0.0.0.0 \
    AUDIT_PORT=8080 \
    AUDIT_DATA_DIR=/data

WORKDIR /srv

# 运行时只用标准库；pytest 仅供 verify 单次容器执行代码测试
COPY requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt

COPY app ./app
COPY tests ./tests
COPY scripts ./scripts

RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=5 \
  CMD python -c "import urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=2); sys.exit(0 if r.status==200 else 1)"

CMD ["python", "-m", "app.web"]
