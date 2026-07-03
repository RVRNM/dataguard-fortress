#!/usr/bin/env python3
"""Script to fix test_integration.py for Windows compatibility."""

import re

# Read the file
with open(r'C:\Users\HP\TheSpace\dataguard-fortress\tests\test_integration.py', 'r') as f:
    content = f.read()

# Define the problematic fixture pattern
problematic_pattern = r'@pytest_asyncio\.fixture\nasync def upstream_server\(free_port: int\) -> AsyncGenerator\[tuple\[str, int\], None\]:\n\s+def protocol_factory\(\):\n\s+proto = asyncio\.Protocol\(\)\n\s+def connection_mame\(transport\):\n\s+pass\n\s+def data_received\(data\):\n\s+body = b\{"status": "ok", "proxied": true\}\n\s+response = \(\n\s+b"HTTP/1\.1 200 OK\\r\\n"\n\s+b"Content-Type: application/json\\r\\n"\n\s+b"Content-Length: "\n\s+\+ str\(len\(body\)\)\.encode\(\n\s+\+ b"\\r\\n"\n\s+\+ b"\\r\\n"\n\s+\+ body\n\s+\)\n\s+transport\.write\(response\)\n\s+transport\.close\(\)\n\s+proto\.connection_made = connection_made\n\s+proto\.data_received = data_received\n\s+return proto\n\n\s+loop = asyncio\.get_event_loop\(\)\n\s+server = await loop\.create_server\(protocol_factory, "127\.0\.0\.1", free_port\)\n\s+await server\.start_serving\(\)\n\s+yield \("127\.0\.0\.1", free_port\)\n\s+server\.close\(\)\n\s+await server\.wait_closed\(\)'

# Define the replacement (Windows-compatible version)
replacement = '''class MockUpstreamProtocol(asyncio.Protocol):
    """Concrete protocol class for mock upstream server - Windows-compatible."""
    
    def __init__(self):
        self.transport = None
    
    def connection_made(self, transport):
        self.transport = transport
    
    def data_received(self, data):
        body = b'{"status": "ok", "proxied": true}'
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n"
            + body
        )
        self.transport.write(response)
        self.transport.close()
    
    def connection_lost(self, exc):
        pass


@pytest_asyncio.fixture
async def upstream_server(free_port: int) -> AsyncGenerator[tuple[str, int], None]:
    """Start a mock upstream server for testing - Windows-compatible."""
    loop = asyncio.get_event_loop()
    server = await loop.create_server(MockUpstreamProtocol, "127.0.0.1", free_port)
    await server.start_serving()
    yield ("127.0.0.1", free_port)
    server.close()
    await server.wait_closed()'''

# Apply the replacement
import re
updated_content = re.sub(
    r'@pytest_asyncio\.fixture\nasync def upstream_server\(free_port: int\) -> AsyncGenerator\[tuple\[str, int\], None\]:[\s\S]*?await server\.wait_closed\(\)',
    replacement,
    content,
    flags=re.MULTILINE
)

# Write back
with open(r'C:\Users\HP\TheSpace\dataguard-fortress\tests\test_integration.py', 'w') as f:
    f.write(updated_content)

print("✓ test_integration.py updated successfully")