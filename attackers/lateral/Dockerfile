FROM python:3.12-slim
RUN apt-get update -qq && apt-get install -y -qq curl nmap util-linux && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir flask==3.0.3
WORKDIR /
COPY server.py /server.py
COPY attack.sh /attack.sh
RUN chmod +x /attack.sh
HEALTHCHECK --interval=5s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"
CMD ["python", "/server.py"]
