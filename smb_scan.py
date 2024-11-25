import argparse
from ms17_10.check_ms17_10 import check_ms17_10

def create_parser():
    parser = argparse.ArgumentParser(description="Check SMB vulnerabilities.")
    parser.add_argument("ip", type=str, help="IP address of the target to check for SMB vulnerabilities.")
    parser.add_argument("--port", type=int, default=445, help="Port to use for SMB (default is 445).")
    parser.add_argument("--username", type=str, default="", help="Port to use for SMB (default is '').")
    parser.add_argument("--password", type=str, default="", help="Port to use for SMB (default is '').")
    return parser

def main():
    parser = create_parser()
    args = parser.parse_args()
    ip = args.ip
    port = args.port
    username = args.username
    password = args.password
    delimiter = '*' * 30
    print(f"[*] Checking SMB vulnerabilities for IP: {ip} on port {port}")
    print(delimiter)
    print(f"[*] Checking for the MS17-010 exploits")
    print(f"[*] [*] EternalBlue, EternalRomance, SMBRelay (CVE-2017-0143, CVE-2017-0144, CVE-2017-0145)")
    check_ms17_10(ip, port, username, password)
    print(delimiter)

if __name__ == "__main__":
    main()
