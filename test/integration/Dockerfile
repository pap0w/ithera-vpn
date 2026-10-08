FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    iproute2 \
    iputils-ping \
    tcpdump \
    procps \
    golang-go \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY . /workspace

RUN chmod +x test/integration/run_poc.sh

CMD ["/bin/bash", "test/integration/run_poc.sh"]
