FROM golang:1.26-bookworm

# Install system deps
RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    ca-certificates \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Install air (prebuilt binary → avoids Go install issues)
RUN curl -sSfL https://raw.githubusercontent.com/air-verse/air/master/install.sh \
    | sh -s -- -b /usr/local/bin

# Create workspace
# WORKDIR /workspace

RUN mkdir -p /workspace/.data && chown -R $(id -u):$(id -g) /workspace/.data

# Optional: cache modules early (faster rebuilds)
#COPY start.sh go.mod go.sum* ./
RUN go mod download || true
RUN go install github.com/go-delve/delve/cmd/dlv@latest

# Copy rest of project
#COPY . .

EXPOSE 53/udp
EXPOSE 53/tcp
EXPOSE 8080
ENV LISTEN_ADDR=0.0.0.0:53

#RUN chmod +x start.sh
#CMD ["./start.sh"]


 