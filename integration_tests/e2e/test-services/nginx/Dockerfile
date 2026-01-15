# Nginx test service with HTTP and HTTPS endpoints
FROM nginx:1.25-alpine

# Install openssl for certificate generation
RUN apk add --no-cache openssl

# Create directory for certificates
RUN mkdir -p /etc/nginx/certs

# Generate self-signed TLS certificates
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/certs/server.key \
    -out /etc/nginx/certs/server.crt \
    -subj "/C=US/ST=Test/L=Test/O=Buckwild/OU=Test/CN=nginx-test"

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Expose HTTP and HTTPS ports
EXPOSE 80 443

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
