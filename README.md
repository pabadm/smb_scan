# smb_scan

usage: python3 smb_scan.py <TARGET_IP> [--port TARGET_PORT] [--username USERNAME] [--password PASSWORD]

Scan target system for SMB vulnerabilities.

positional arguments:
  ip                   IP address of the target to check for SMB vulnerabilities.

options:
  --port PORT          Port to use for SMB (default is 445).
  --username USERNAME  Port to use for SMB (default is '').
  --password PASSWORD  Port to use for SMB (default is '').
