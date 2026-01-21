#!/usr/bin/env python3
"""
locksmith.py - Multi-Protocol Credential Testing Tool
Author: Penetration Testing Toolkit
Purpose: Test username/password credentials across multiple services
"""

import argparse
import subprocess
import sys
from typing import List, Dict, Tuple
import shutil

# ANSI Color Codes
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Port to protocol mapping
PORT_PROTOCOLS = {
    21: {'protocol': 'ftp', 'name': 'FTP'},
    22: {'protocol': 'ssh', 'name': 'SSH'},
    23: {'protocol': 'telnet', 'name': 'Telnet'},
    88: {'protocol': 'smb', 'name': 'Kerberos/SMB'},
    139: {'protocol': 'smb', 'name': 'NetBIOS/SMB'},
    389: {'protocol': 'ldap', 'name': 'LDAP'},
    445: {'protocol': 'smb', 'name': 'SMB'},
    636: {'protocol': 'ldap', 'name': 'LDAPS'},
    1433: {'protocol': 'mssql', 'name': 'MSSQL'},
    3306: {'protocol': 'mysql', 'name': 'MySQL'},
    3389: {'protocol': 'rdp', 'name': 'RDP'},
    5432: {'protocol': 'postgres', 'name': 'PostgreSQL'},
    5985: {'protocol': 'winrm', 'name': 'WinRM'},
    5986: {'protocol': 'winrm', 'name': 'WinRM-HTTPS'},
}

def print_banner():
    """Print tool banner"""
    banner = f"""
{Colors.OKCYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║                    LOCKSMITH v1.0                         ║
║          Multi-Protocol Credential Testing Tool           ║
║                  OSCP Edition - 2025                      ║
╚═══════════════════════════════════════════════════════════╝
{Colors.ENDC}"""
    print(banner)

def check_dependencies():
    """Check if NetExec (nxc) is installed"""
    if not shutil.which('nxc') and not shutil.which('netexec'):
        print(f"{Colors.FAIL}[!] Error: NetExec (nxc) not found!{Colors.ENDC}")
        print(f"{Colors.WARNING}[*] Install with: sudo apt install netexec{Colors.ENDC}")
        sys.exit(1)
    
    # Prefer 'nxc' command if available
    return 'nxc' if shutil.which('nxc') else 'netexec'

def parse_ports(ports_str: str) -> List[int]:
    """Parse comma-separated port string into list of integers"""
    try:
        ports = [int(p.strip()) for p in ports_str.split(',')]
        return ports
    except ValueError:
        print(f"{Colors.FAIL}[!] Invalid port format. Use: 22,445,3389{Colors.ENDC}")
        sys.exit(1)

def get_supported_ports(ports: List[int]) -> List[int]:
    """Filter only supported ports that have protocol mappings"""
    supported = []
    unsupported = []
    
    for port in ports:
        if port in PORT_PROTOCOLS:
            supported.append(port)
        else:
            unsupported.append(port)
    
    if unsupported:
        print(f"{Colors.WARNING}[*] Unsupported ports (skipped): {', '.join(map(str, unsupported))}{Colors.ENDC}")
    
    return supported

def test_credential(nxc_cmd: str, target: str, username: str, password: str, 
                   port: int, protocol: str) -> Tuple[bool, str]:
    """Test a single credential against a protocol"""
    
    # Build command based on protocol
    if protocol == 'smb':
        cmd = [nxc_cmd, 'smb', target, '-u', username, '-p', password, '-d', '.']
    elif protocol == 'ssh':
        cmd = [nxc_cmd, 'ssh', target, '-u', username, '-p', password]
    elif protocol == 'ftp':
        cmd = [nxc_cmd, 'ftp', target, '-u', username, '-p', password]
    elif protocol == 'rdp':
        cmd = [nxc_cmd, 'rdp', target, '-u', username, '-p', password]
    elif protocol == 'winrm':
        cmd = [nxc_cmd, 'winrm', target, '-u', username, '-p', password]
    elif protocol == 'mssql':
        cmd = [nxc_cmd, 'mssql', target, '-u', username, '-p', password]
    elif protocol == 'ldap':
        cmd = [nxc_cmd, 'ldap', target, '-u', username, '-p', password]
    elif protocol == 'mysql':
        cmd = [nxc_cmd, 'mysql', target, '-u', username, '-p', password]
    else:
        return False, "Protocol not supported"
    
    # Add port specification if not default
    default_ports = {
        'smb': 445,
        'ssh': 22,
        'ftp': 21,
        'rdp': 3389,
        'winrm': 5985,
        'mssql': 1433,
        'ldap': 389,
        'mysql': 3306
    }
    
    if port != default_ports.get(protocol, port):
        cmd.extend(['--port', str(port)])
    
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            text=True
        )
        
        output = result.stdout + result.stderr
        
        # Check for success indicators in NetExec output
        success_indicators = [
            '(Pwn3d!)',
            'STATUS_SUCCESS',
            '[+]',
        ]
        
        # Check for failure indicators
        failure_indicators = [
            'STATUS_LOGON_FAILURE',
            'Authentication failed',
            'Login failed',
            'Connection error',
            'NT_STATUS_LOGON_FAILURE',
            '[-]'
        ]
        
        # Determine success
        is_success = any(indicator in output for indicator in success_indicators)
        is_failure = any(indicator in output for indicator in failure_indicators)
        
        if is_success and not is_failure:
            return True, output
        else:
            return False, output
            
    except subprocess.TimeoutExpired:
        return False, "Connection timeout"
    except Exception as e:
        return False, f"Error: {str(e)}"

def get_example_command(port: int, protocol: str, target: str, username: str, password: str) -> str:
    """Generate example connection command for successful authentication"""
    commands = {
        21: f"ftp {target}  # then login with {username}",
        22: f"ssh {username}@{target}",
        139: f"nxc smb {target} -u '{username}' -p '{password}' --shares",
        389: f"ldapsearch -x -H ldap://{target} -D '{username}' -w '{password}' -b 'dc=domain,dc=com'",
        445: f"nxc smb {target} -u '{username}' -p '{password}' --shares",
        636: f"ldapsearch -x -H ldaps://{target} -D '{username}' -w '{password}' -b 'dc=domain,dc=com'",
        1433: f"nxc mssql {target} -u '{username}' -p '{password}' -q 'SELECT @@version'",
        3306: f"mysql -h {target} -u {username} -p'{password}'",
        3389: f"xfreerdp /u:{username} /p:{password} /v:{target} /cert:ignore",
        5432: f"psql -h {target} -U {username} -d postgres",
        5985: f"evil-winrm -i {target} -u '{username}' -p '{password}'",
        5986: f"evil-winrm -i {target} -u '{username}' -p '{password}' -S",
    }
    return commands.get(port, f"# Connect to {target}:{port}")

def print_test_result(port: int, protocol_name: str, success: bool, output: str, 
                     target: str = "", username: str = "", password: str = ""):
    """Print formatted test result"""
    if success:
        print(f"{Colors.OKGREEN}[✓] SUCCESS{Colors.ENDC} - Port {Colors.BOLD}{port}{Colors.ENDC} ({protocol_name})")
        print(f"{Colors.OKCYAN}    └─ Credentials are valid!{Colors.ENDC}")
        if '(Pwn3d!)' in output:
            print(f"{Colors.WARNING}    └─ {Colors.BOLD}ADMIN ACCESS DETECTED!{Colors.ENDC}")
        
        # Add example command
        if target and username and password:
            example_cmd = get_example_command(port, protocol_name, target, username, password)
            print(f"{Colors.OKBLUE}    └─ Example: {Colors.ENDC}{example_cmd}")
    else:
        print(f"{Colors.FAIL}[✗] FAILED{Colors.ENDC}  - Port {Colors.BOLD}{port}{Colors.ENDC} ({protocol_name})")
        if "timeout" in output.lower():
            print(f"{Colors.WARNING}    └─ Connection timeout{Colors.ENDC}")
        elif "connection" in output.lower():
            print(f"{Colors.WARNING}    └─ Connection error (port may be filtered/closed){Colors.ENDC}")

def main():
    parser = argparse.ArgumentParser(
        description='Test credentials across multiple protocols using NetExec',
        epilog='Example: ./locksmith.py -t 10.10.10.11 -u "admin" -p "password" -ports 22,445,3389'
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target IP address')
    parser.add_argument('-u', '--username', required=True, help='Username to test')
    parser.add_argument('-p', '--password', required=True, help='Password to test')
    parser.add_argument('-ports', '--ports', required=True, help='Comma-separated ports (e.g., 22,445,3389)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Check dependencies
    nxc_cmd = check_dependencies()
    
    # Parse and validate ports
    ports = parse_ports(args.ports)
    supported_ports = get_supported_ports(ports)
    
    if not supported_ports:
        print(f"{Colors.FAIL}[!] No supported ports to test!{Colors.ENDC}")
        sys.exit(1)
    
    # Print test information
    print(f"{Colors.BOLD}[*] Test Configuration:{Colors.ENDC}")
    print(f"    Target:   {Colors.OKCYAN}{args.target}{Colors.ENDC}")
    print(f"    Username: {Colors.OKCYAN}{args.username}{Colors.ENDC}")
    print(f"    Password: {Colors.OKCYAN}{'*' * len(args.password)}{Colors.ENDC}")
    print(f"    Ports:    {Colors.OKCYAN}{', '.join(map(str, supported_ports))}{Colors.ENDC}")
    print()
    print(f"{Colors.BOLD}[*] Starting credential tests...{Colors.ENDC}")
    print(f"{Colors.BOLD}{'=' * 60}{Colors.ENDC}\n")
    
    # Test each port
    successful_ports = []
    failed_ports = []
    
    for port in supported_ports:
        protocol_info = PORT_PROTOCOLS[port]
        protocol = protocol_info['protocol']
        protocol_name = protocol_info['name']
        
        print(f"{Colors.OKBLUE}[*] Testing Port {port} ({protocol_name})...{Colors.ENDC}")
        
        success, output = test_credential(
            nxc_cmd,
            args.target,
            args.username,
            args.password,
            port,
            protocol
        )
        
        print_test_result(port, protocol_name, success, output, args.target, args.username, args.password)
        
        if args.verbose and output:
            print(f"{Colors.WARNING}    [Verbose Output]:{Colors.ENDC}")
            for line in output.split('\n')[:5]:  # Show first 5 lines
                if line.strip():
                    print(f"    {line}")
        
        print()
        
        if success:
            successful_ports.append((port, protocol_name))
        else:
            failed_ports.append((port, protocol_name))
    
    # Print summary
    print(f"{Colors.BOLD}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.BOLD}[*] Test Summary:{Colors.ENDC}\n")
    
    if successful_ports:
        print(f"{Colors.OKGREEN}{Colors.BOLD}✓ SUCCESSFUL AUTHENTICATIONS:{Colors.ENDC}")
        for port, name in successful_ports:
            print(f"  {Colors.OKGREEN}→ Port {port} ({name}){Colors.ENDC}")
        print()
    
    if failed_ports:
        print(f"{Colors.FAIL}{Colors.BOLD}✗ FAILED AUTHENTICATIONS:{Colors.ENDC}")
        for port, name in failed_ports:
            print(f"  {Colors.FAIL}→ Port {port} ({name}){Colors.ENDC}")
        print()
    
    # Final statistics
    total = len(supported_ports)
    success_count = len(successful_ports)
    fail_count = len(failed_ports)
    
    print(f"{Colors.BOLD}[*] Statistics:{Colors.ENDC}")
    print(f"    Total Tests:  {total}")
    print(f"    {Colors.OKGREEN}Successful:   {success_count}{Colors.ENDC}")
    print(f"    {Colors.FAIL}Failed:       {fail_count}{Colors.ENDC}")
    print()
    
    if successful_ports:
        print(f"{Colors.OKGREEN}{Colors.BOLD}[+] Credentials are VALID on {success_count} service(s)!{Colors.ENDC}")
    else:
        print(f"{Colors.FAIL}[!] Credentials failed on all tested services.{Colors.ENDC}")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Interrupted by user.{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")
        sys.exit(1)
