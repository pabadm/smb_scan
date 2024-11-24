# smb_scan

A tool to scan a target system for SMB vulnerabilities.

## Usage

python3 smb_scan.py <TARGET_IP> [--port TARGET_PORT] [--username USERNAME] [--password PASSWORD]

### Positional arguments:

- TARGET_IP  
  The IP address of the target system to check for SMB vulnerabilities.

### Optional arguments:

- --port PORT  
  The port to use for SMB. (Default: 445)

- --username USERNAME  
  The username for authentication. (Default: "")

- --password PASSWORD  
  The password for authentication. (Default: "")
