FROM node:18-alpine

WORKDIR /app

# Install system dependencies
RUN apk add --no-cache \
    git \
    openssh-client \
    curl \
    jq \
    bash \
    openssl

# Create necessary directories
RUN mkdir -p /app/logs /app/cache /root/.ssh

# Copy package files
COPY package.json ./
RUN npm install

# Copy application files
COPY server.js ./

# Set up Git configuration
RUN git config --global user.name "MCP GitLab Bot" && \
    git config --global user.email "mcp-bot@snpb.app" && \
    git config --global init.defaultBranch main

# Set proper permissions
RUN chmod 700 /root/.ssh

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3333/health || exit 1

EXPOSE 3333 3334

CMD ["npm", "start"]
