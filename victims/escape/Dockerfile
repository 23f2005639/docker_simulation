FROM ubuntu:22.04
RUN apt-get update -qq && apt-get install -y -qq procps && rm -rf /var/lib/apt/lists/*
# Intentional misconfiguration: WORKDIR points into /proc/self/fd
WORKDIR /proc/self/fd
LABEL scenario="container-escape" misconfiguration="workdir-proc-fd"
CMD ["sleep", "infinity"]
