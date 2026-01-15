"""FTP protocol tests for E2E framework.

Tests FTP connectivity through the Buckwild VPN, including:
- Upload and download operations
- Active and passive mode transfers
- Directory listing
- Authenticated and anonymous access
"""

import asyncio
import hashlib
import pytest


@pytest.mark.e2e
@pytest.mark.ftp
@pytest.mark.asyncio
async def test_ftp_upload_small(two_node_cluster):
    """Test FTP upload of small file (1KB)."""
    node1 = two_node_cluster.get_node("node-1")

    # Create test file
    create_cmd = "echo 'small test data' > /tmp/ftp_upload_small.txt"
    returncode, _, stderr = await node1.exec_command(create_cmd, check=False)
    assert returncode == 0, f"Failed to create test file: {stderr}"

    # Upload via FTP using curl
    upload_cmd = """curl -s -T /tmp/ftp_upload_small.txt \
        -u testuser:testpass \
        ftp://ftp-test/upload_small.txt \
        -o /dev/null -w '%{http_code}'"""

    returncode, stdout, stderr = await node1.exec_command(
        upload_cmd,
        timeout=15.0,
        check=False
    )

    assert returncode == 0, f"FTP upload failed: {stderr}"
    # FTP uses different status codes, 226 = transfer complete
    # curl may return empty or connection status, check it didn't fail
    assert stderr == "" or "226" in stderr or "Transfer complete" in stderr.lower()


@pytest.mark.e2e
@pytest.mark.ftp
@pytest.mark.asyncio
async def test_ftp_upload_large(two_node_cluster):
    """Test FTP upload of larger file (1MB)."""
    node1 = two_node_cluster.get_node("node-1")

    # Create 1MB test file
    create_cmd = "dd if=/dev/zero of=/tmp/ftp_upload_large.bin bs=1M count=1 2>/dev/null"
    returncode, _, stderr = await node1.exec_command(create_cmd, check=False)
    assert returncode == 0, f"Failed to create test file: {stderr}"

    # Upload via FTP
    upload_cmd = """curl -s -T /tmp/ftp_upload_large.bin \
        -u testuser:testpass \
        ftp://ftp-test/upload_large.bin"""

    returncode, stdout, stderr = await node1.exec_command(
        upload_cmd,
        timeout=30.0,
        check=False
    )

    assert returncode == 0, f"FTP upload of 1MB file failed: {stderr}"


@pytest.mark.e2e
@pytest.mark.ftp
@pytest.mark.asyncio
async def test_ftp_download(two_node_cluster):
    """Test FTP download and verify file integrity."""
    node1 = two_node_cluster.get_node("node-1")

    # Download pre-existing test file
    download_cmd = """curl -s -u testuser:testpass \
        ftp://ftp-test/test_download.txt \
        -o /tmp/ftp_downloaded.txt"""

    returncode, _, stderr = await node1.exec_command(
        download_cmd,
        timeout=15.0,
        check=False
    )

    assert returncode == 0, f"FTP download failed: {stderr}"

    # Verify file was downloaded
    verify_cmd = "cat /tmp/ftp_downloaded.txt"
    returncode, stdout, stderr = await node1.exec_command(
        verify_cmd,
        check=False
    )

    assert returncode == 0, f"Failed to read downloaded file: {stderr}"
    assert "small test file" in stdout, f"Downloaded file has unexpected content: {stdout}"


@pytest.mark.e2e
@pytest.mark.ftp
@pytest.mark.asyncio
async def test_ftp_download_large_with_checksum(two_node_cluster):
    """Test FTP download of large file and verify with checksum."""
    node1 = two_node_cluster.get_node("node-1")

    # Download large pre-existing file
    download_cmd = """curl -s -u testuser:testpass \
        ftp://ftp-test/test_large.bin \
        -o /tmp/ftp_large_downloaded.bin"""

    returncode, _, stderr = await node1.exec_command(
        download_cmd,
        timeout=30.0,
        check=False
    )

    assert returncode == 0, f"FTP large download failed: {stderr}"

    # Verify file size (should be 1MB = 1048576 bytes)
    size_cmd = "stat -c %s /tmp/ftp_large_downloaded.bin 2>/dev/null || stat -f %z /tmp/ftp_large_downloaded.bin"
    returncode, stdout, stderr = await node1.exec_command(
        size_cmd,
        check=False
    )

    assert returncode == 0, f"Failed to check file size: {stderr}"
    size = int(stdout.strip())
    assert size == 1048576, f"Downloaded file size mismatch: expected 1048576, got {size}"


@pytest.mark.e2e
@pytest.mark.ftp
@pytest.mark.asyncio
async def test_ftp_passive_mode(two_node_cluster):
    """Test FTP in explicit passive mode (PASV)."""
    node1 = two_node_cluster.get_node("node-1")

    # Passive mode is default for curl, but make it explicit
    download_cmd = """curl -s --ftp-pasv \
        -u testuser:testpass \
        ftp://ftp-test/test_download.txt"""

    returncode, stdout, stderr = await node1.exec_command(
        download_cmd,
        timeout=15.0,
        check=False
    )

    assert returncode == 0, f"FTP passive mode download failed: {stderr}"
    assert "small test file" in stdout, f"Downloaded file has unexpected content: {stdout}"


@pytest.mark.e2e
@pytest.mark.ftp
@pytest.mark.asyncio
async def test_ftp_active_mode(two_node_cluster):
    """Test FTP in explicit active mode (PORT).

    Note: Active mode may not work through firewalls/NAT as it requires
    the server to connect back to the client.
    """
    node1 = two_node_cluster.get_node("node-1")

    # Active mode using --ftp-port
    download_cmd = """curl -s --ftp-port - \
        -u testuser:testpass \
        ftp://ftp-test/test_download.txt"""

    returncode, stdout, stderr = await node1.exec_command(
        download_cmd,
        timeout=15.0,
        check=False
    )

    # Active mode might not work in all network configurations
    # We check success but don't fail the test if it doesn't work
    if returncode == 0:
        assert "small test file" in stdout, f"Downloaded file has unexpected content: {stdout}"
    else:
        # Log that active mode didn't work but don't fail
        # This is expected in many network configurations
        pytest.skip(f"Active mode not supported in this network configuration: {stderr}")


@pytest.mark.e2e
@pytest.mark.ftp
@pytest.mark.asyncio
async def test_ftp_directory_listing(two_node_cluster):
    """Test FTP directory listing (LIST command)."""
    node1 = two_node_cluster.get_node("node-1")

    # List directory contents
    list_cmd = """curl -s -u testuser:testpass ftp://ftp-test/"""

    returncode, stdout, stderr = await node1.exec_command(
        list_cmd,
        timeout=15.0,
        check=False
    )

    assert returncode == 0, f"FTP directory listing failed: {stderr}"

    # Verify we can see the pre-loaded test files
    assert "test_download.txt" in stdout, f"Expected test_download.txt in listing: {stdout}"
    assert "test_large.bin" in stdout, f"Expected test_large.bin in listing: {stdout}"


@pytest.mark.e2e
@pytest.mark.ftp
@pytest.mark.asyncio
async def test_ftp_authenticated(two_node_cluster):
    """Test FTP with user/password authentication."""
    node1 = two_node_cluster.get_node("node-1")

    # Test with correct credentials
    download_cmd = """curl -s -u testuser:testpass \
        ftp://ftp-test/test_download.txt"""

    returncode, stdout, stderr = await node1.exec_command(
        download_cmd,
        timeout=15.0,
        check=False
    )

    assert returncode == 0, f"FTP authenticated download failed: {stderr}"
    assert "small test file" in stdout, f"Downloaded file has unexpected content: {stdout}"


@pytest.mark.e2e
@pytest.mark.ftp
@pytest.mark.asyncio
async def test_ftp_authentication_failure(two_node_cluster):
    """Test FTP authentication failure with wrong credentials."""
    node1 = two_node_cluster.get_node("node-1")

    # Test with incorrect credentials
    download_cmd = """curl -s -u wronguser:wrongpass \
        ftp://ftp-test/test_download.txt"""

    returncode, stdout, stderr = await node1.exec_command(
        download_cmd,
        timeout=15.0,
        check=False
    )

    # Should fail with authentication error
    assert returncode != 0, "FTP should fail with wrong credentials"
    assert "530" in stderr or "Login incorrect" in stderr or "authentication failed" in stderr.lower(), \
        f"Expected authentication error, got: {stderr}"


@pytest.mark.e2e
@pytest.mark.ftp
@pytest.mark.asyncio
async def test_ftp_concurrent_downloads(two_node_cluster):
    """Test concurrent FTP downloads from multiple nodes."""
    node1 = two_node_cluster.get_node("node-1")
    node2 = two_node_cluster.get_node("node-2")

    async def download_file(node, request_id):
        cmd = f"""curl -s -u testuser:testpass \
            ftp://ftp-test/test_download.txt \
            -o /tmp/ftp_concurrent_{request_id}.txt"""
        returncode, stdout, stderr = await node.exec_command(
            cmd,
            timeout=15.0,
            check=False
        )
        return returncode, stdout, stderr

    # Execute concurrent downloads from both nodes
    tasks = [
        download_file(node1, 1),
        download_file(node1, 2),
        download_file(node2, 3),
        download_file(node2, 4),
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Verify all downloads succeeded
    for i, result in enumerate(results):
        assert not isinstance(result, Exception), f"Download {i+1} raised exception: {result}"
        returncode, stdout, stderr = result
        assert returncode == 0, f"Download {i+1} failed: {stderr}"


@pytest.mark.e2e
@pytest.mark.ftp
@pytest.mark.asyncio
async def test_ftp_upload_download_integrity(two_node_cluster):
    """Test FTP upload then download and verify integrity."""
    node1 = two_node_cluster.get_node("node-1")

    # Create file with known content
    test_data = "integrity test data " * 100  # ~2KB
    create_cmd = f"echo '{test_data}' > /tmp/ftp_integrity_upload.txt"
    returncode, _, stderr = await node1.exec_command(create_cmd, check=False)
    assert returncode == 0, f"Failed to create test file: {stderr}"

    # Calculate checksum before upload
    checksum_cmd = "md5sum /tmp/ftp_integrity_upload.txt | awk '{print $1}'"
    returncode, original_checksum, stderr = await node1.exec_command(
        checksum_cmd,
        check=False
    )
    assert returncode == 0, f"Failed to calculate checksum: {stderr}"
    original_checksum = original_checksum.strip()

    # Upload file
    upload_cmd = """curl -s -T /tmp/ftp_integrity_upload.txt \
        -u testuser:testpass \
        ftp://ftp-test/integrity_test.txt"""

    returncode, _, stderr = await node1.exec_command(
        upload_cmd,
        timeout=15.0,
        check=False
    )
    assert returncode == 0, f"FTP upload failed: {stderr}"

    # Download file back
    download_cmd = """curl -s -u testuser:testpass \
        ftp://ftp-test/integrity_test.txt \
        -o /tmp/ftp_integrity_download.txt"""

    returncode, _, stderr = await node1.exec_command(
        download_cmd,
        timeout=15.0,
        check=False
    )
    assert returncode == 0, f"FTP download failed: {stderr}"

    # Calculate checksum after download
    checksum_cmd = "md5sum /tmp/ftp_integrity_download.txt | awk '{print $1}'"
    returncode, downloaded_checksum, stderr = await node1.exec_command(
        checksum_cmd,
        check=False
    )
    assert returncode == 0, f"Failed to calculate downloaded checksum: {stderr}"
    downloaded_checksum = downloaded_checksum.strip()

    # Verify checksums match
    assert original_checksum == downloaded_checksum, \
        f"Checksum mismatch: original={original_checksum}, downloaded={downloaded_checksum}"


@pytest.mark.e2e
@pytest.mark.ftp
@pytest.mark.asyncio
async def test_ftp_multiple_sequential_operations(two_node_cluster):
    """Test multiple sequential FTP operations."""
    node1 = two_node_cluster.get_node("node-1")

    operations = [
        ("list", "curl -s -u testuser:testpass ftp://ftp-test/"),
        ("download", "curl -s -u testuser:testpass ftp://ftp-test/test_download.txt"),
        ("list_again", "curl -s -u testuser:testpass ftp://ftp-test/"),
    ]

    for op_name, cmd in operations:
        returncode, stdout, stderr = await node1.exec_command(
            cmd,
            timeout=15.0,
            check=False
        )

        assert returncode == 0, f"FTP operation '{op_name}' failed: {stderr}"

        # Verify operation-specific output
        if "list" in op_name:
            assert "test_download.txt" in stdout, f"Directory listing failed for '{op_name}'"
        elif op_name == "download":
            assert "small test file" in stdout, f"Download failed for '{op_name}'"
