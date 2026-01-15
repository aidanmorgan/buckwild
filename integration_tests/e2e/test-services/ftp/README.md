# FTP Test Service

FTP test service for E2E protocol testing using pure-ftpd.

## Overview

This service provides FTP (port 21) with both anonymous and authenticated access for testing the Buckwild VPN protocol's ability to handle FTP traffic in both active and passive modes.

## Configuration

### Ports

- **21**: FTP control connection
- **30000-30009**: Passive mode data transfer ports

### Authentication

#### Authenticated User
- Username: `testuser`
- Password: `testpass`
- Home directory: `/home/ftpusers/testuser`

#### Anonymous Access
- Anonymous read-only access is enabled
- No password required

### Pre-loaded Files

The following test files are available in the testuser home directory:

- `test_download.txt` - Small text file for basic download testing
- `test_large.bin` - 1MB binary file for throughput testing

## FTP Modes

### Passive Mode (PASV)

Passive mode is recommended for testing through NAT/firewalls. The server uses ports 30000-30009 for data connections.

### Active Mode (PORT)

Active mode requires the client to accept incoming connections. May not work through firewalls.

## Building

```bash
cd integration_tests/e2e/test-services/ftp
docker build -t buckwild-ftp-test .
```

## Running Standalone

```bash
docker run -p 21:21 -p 30000-30009:30000-30009 buckwild-ftp-test
```

## Usage in Tests

The FTP service is intended to be used within E2E test scenarios, deployed as part of a Docker Compose network alongside Buckwild nodes.

Example test pattern:

```python
@pytest.mark.e2e
@pytest.mark.ftp
async def test_ftp_upload(two_node_cluster):
    node = two_node_cluster.get_node("node-1")

    # Create test file
    await node.exec_command("echo 'test data' > /tmp/upload.txt")

    # Upload via FTP
    cmd = """curl -T /tmp/upload.txt ftp://testuser:testpass@ftp-test/upload.txt"""
    returncode, stdout, stderr = await node.exec_command(cmd)

    assert returncode == 0
```

## Testing with curl

The tests use `curl` for FTP operations:

### Download
```bash
curl -u testuser:testpass ftp://ftp-test/test_download.txt
```

### Upload
```bash
curl -T localfile.txt -u testuser:testpass ftp://ftp-test/remotefile.txt
```

### List directory
```bash
curl -u testuser:testpass ftp://ftp-test/
```

### Passive mode (default)
```bash
curl --ftp-pasv -u testuser:testpass ftp://ftp-test/file.txt
```

### Active mode
```bash
curl --ftp-port - -u testuser:testpass ftp://ftp-test/file.txt
```

## Notes

- Pure-ftpd is lightweight and designed for testing
- Passive mode port range is limited to 10 ports (30000-30009)
- Anonymous access is read-only for security
- All authenticated operations use testuser/testpass credentials
- Files uploaded by tests are stored in `/home/ftpusers/testuser`
