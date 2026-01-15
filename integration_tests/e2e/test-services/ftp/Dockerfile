# FTP test service using pure-ftpd
FROM stilliard/pure-ftpd:latest

# Create FTP user directory
RUN mkdir -p /home/ftpusers/testuser

# Create test files for download testing
RUN echo "small test file" > /home/ftpusers/testuser/test_download.txt && \
    dd if=/dev/zero of=/home/ftpusers/testuser/test_large.bin bs=1M count=1 2>/dev/null && \
    chown -R ftpuser:ftpgroup /home/ftpusers/testuser

# Expose FTP ports
# 21: FTP control
# 30000-30009: Passive mode data ports
EXPOSE 21 30000-30009

# Configure pure-ftpd for testing
# -c 10: max 10 simultaneous users
# -C 5: max 5 connections per IP
# -l puredb:/etc/pure-ftpd/pureftpd.pdb: use puredb authentication
# -E: allow anonymous read-only access
# -j: create home directories if they don't exist
# -p 30000:30009: passive port range
ENV PUBLICHOST=localhost
ENV FTP_USER_NAME=testuser
ENV FTP_USER_PASS=testpass
ENV FTP_USER_HOME=/home/ftpusers/testuser
ENV ADDED_FLAGS="-d -d"

# Health check
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
    CMD nc -z localhost 21 || exit 1

# Start pure-ftpd
CMD ["/run.sh", "-c", "10", "-C", "5", "-l", "puredb:/etc/pure-ftpd/pureftpd.pdb", "-E", "-j", "-p", "30000:30009"]
