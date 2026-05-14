FROM ubuntu:22.04
RUN apt-get update -qq && apt-get install -y -qq curl && rm -rf /var/lib/apt/lists/*
# Intentional misconfiguration: /var/run/docker.sock mounted in docker-compose.yml
LABEL scenario="docker-socket-abuse" misconfiguration="docker-sock-mount"
CMD ["sleep", "infinity"]
