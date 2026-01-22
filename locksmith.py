#!/usr/bin/env python3
"""
locksmith.py - Multi-Protocol Credential Testing Tool
Author: Penetration Testing Toolkit
Purpose: Test username/password credentials across multiple services
Version: 1.2 (Telnet Support Added)
"""

import argparse
import subprocess
import sys
from typing import List, Tuple
import shutil
import tempfile
import os

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
    88: {'protocol': 'smb', 'name': 'Kerberos'},
    139: {'protocol': 'smb', 'name': 'NetBIOS'},
    389: {'protocol': 'ldap', 'name': 'LDAP'},
    445: {'protocol': 'smb', 'name': 'SMB'},
    636: {'protocol': 'ldaps', 'name': 'LDAPS'},
    1433: {'protocol': 'mssql', 'name': 'MSSQL'},
    3306: {'protocol': 'mysql', 'name': 'MySQL'},
    3389: {'protocol': 'rdp', 'name': 'RDP'},
    5432: {'protocol': 'postgres', 'name': 'PostgreSQL'},
    5900: {'protocol': 'vnc', 'name': 'VNC'},
    5985: {'protocol': 'winrm', 'name': 'WinRM'},
    5986: {'protocol': 'winrm', 'name': 'WinRM-HTTPS'},
    6379: {'protocol': 'redis', 'name': 'Redis'},
    27017: {'protocol': 'mongodb', 'name': 'MongoDB'},
}

def print_banner():
    """Print tool banner"""
    banner = f"""
{Colors.OKCYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║                    LOCKSMITH v1.2                         ║
║          Multi-Protocol Credential Testing Tool           ║
╚═══════════════════════════════════════════════════════════╝
{Colors.ENDC}"""
    print(banner)

def check_dependencies() -> str:
    """Check if NetExec (nxc) is installed"""
    if not shutil.which('nxc') and not shutil.which('netexec'):
        print(f"{Colors.FAIL}[!] Error: NetExec (nxc) not found!{Colors.ENDC}")
        print(f"{Colors.WARNING}[*] Install with: sudo apt install netexec{Colors.ENDC}")
        print(f"{Colors.WARNING}[*] Or: pipx install netexec{Colors.ENDC}")
        sys.exit(1)
    
    nxc_cmd = 'nxc' if shutil.which('nxc') else 'netexec'
    
    try:
        result = subprocess.run([nxc_cmd, '--version'], 
                              capture_output=True, text=True, timeout=5)
        version = result.stdout.strip()
        print(f"{Colors.OKGREEN}[✓] NetExec found: {version}{Colors.ENDC}\n")
    except:
        print(f"{Colors.OKGREEN}[✓] NetExec found{Colors.ENDC}\n")
    
    return nxc_cmd

def parse_ports(ports_str: str) -> List[int]:
    """Parse comma-separated port string into list of integers"""
    try:
        ports = [int(p.strip()) for p in ports_str.split(',')]
        ports = sorted(list(set(ports)))
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

def validate_target(target: str) -> bool:
    """Validate target IP or hostname"""
    if not target or target.isspace():
        return False
    return True

def test_telnet(target: str, username: str, password: str, port: int = 23) -> Tuple[bool, str]:
    """Test Telnet authentication using expect-like interaction"""
    try:
        # Escape special characters for expect script
        # Tcl/Expect needs strict escaping for " \ and special vars
        safe_username = username.replace('\\', '\\\\').replace('"', '\\"').replace('[', '\\[').replace('$', '\\$')
        safe_password = password.replace('\\', '\\\\').replace('"', '\\"').replace('[', '\\[').replace('$', '\\$')
        
        # Create telnet expect script
        # Note: double braces {{ }} are used for f-string literal braces
        script = f"""#!/usr/bin/expect -f
set timeout 10
spawn telnet {target} {port}
expect {{
    -re "(login|Username|Login):" {{
        send "{safe_username}\\r"
        expect {{
            -re "(Password|password):" {{
                send "{safe_password}\\r"
                expect {{
                    -re "Login incorrect|Authentication failed|Login failed" {{ exit 1 }}
                    -re "\\\\$|#|>" {{ send "exit\\r"; exit 0 }}
                    timeout {{ exit 2 }}
                }}
            }}
            timeout {{ exit 2 }}
        }}
    }}
    -re "Connection refused|Connection closed" {{ exit 3 }}
    timeout {{ exit 2 }}
}}
"""
        
        # Try with expect if available
        if shutil.which('expect'):
            with tempfile.NamedTemporaryFile(mode='w', suffix='.exp', delete=False) as f:
                f.write(script)
                script_path = f.name
            
            try:
                subprocess.run(['chmod', '+x', script_path], check=True, timeout=5)
                result = subprocess.run(['expect', script_path], 
                                      capture_output=True, 
                                      text=True, 
                                      timeout=15)
                
                if result.returncode == 0:
                    return True, "Authentication successful"
                elif result.returncode == 1:
                    return False, "Invalid credentials"
                elif result.returncode == 2:
                    return False, "Connection timeout (Expect)"
                else:
                    return False, f"Connection refused or closed (Code: {result.returncode})"
            finally:
                if os.path.exists(script_path):
                    os.unlink(script_path)
        else:
            # Fallback if expect is not installed
            return False, "Error: 'expect' package not found. Install with: sudo apt install expect"
                
    except subprocess.TimeoutExpired:
        return False, "Connection timeout"
    except Exception as e:
        return False, f"Error: {str(e)}"

def test_credential(nxc_cmd: str, target: str, username: str, password: str, 
                   port: int, protocol: str) -> Tuple[bool, str]:
    """Test a single credential against a protocol"""
    
    if protocol == 'telnet':
        return test_telnet(target, username, password, port)
    
    # Build command based on protocol
    cmd = []
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
    elif protocol == 'ldaps':
        cmd = [nxc_cmd, 'ldap', target, '-u', username, '-p', password, '--use-ldaps']
    elif protocol == 'mysql':
        cmd = [nxc_cmd, 'mysql', target, '-u', username, '-p', password]
    elif protocol == 'postgres':
        cmd = [nxc_cmd, 'postgres', target, '-u', username, '-p', password]
    elif protocol == 'mongodb':
        cmd = [nxc_cmd, 'mongodb', target, '-u', username, '-p', password]
    elif protocol == 'vnc':
        cmd = [nxc_cmd, 'vnc', target, '-u', username, '-p', password]
    elif protocol == 'redis':
        cmd = [nxc_cmd, 'redis', target, '-p', password]
    else:
        return False, f"Protocol '{protocol}' not supported"
    
    # Add port specification if not default
    default_ports = {
        'smb': 445, 'ssh': 22, 'ftp': 21, 'rdp': 3389, 'winrm': 5985,
        'mssql': 1433, 'ldap': 389, 'ldaps': 636, 'mysql': 3306,
        'postgres': 5432, 'vnc': 5900, 'redis': 6379, 'mongodb': 27017
    }
    
    if port != default_ports.get(protocol, port):
        cmd.extend(['--port', str(port)])
    
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            text=True
        )
        
        output = result.stdout + result.stderr
        
        success_indicators = [
            '(Pwn3d!)', 'STATUS_SUCCESS', '[+]',
            'Authentication successful', 'Login successful'
        ]
        
        failure_indicators = [
            'STATUS_LOGON_FAILURE', 'Authentication failed', 'Login failed',
            'Connection error', 'NT_STATUS_LOGON_FAILURE', 'NT_STATUS_ACCESS_DENIED',
            'Invalid credentials', '[-]'
        ]
        
        is_success = any(indicator in output for indicator in success_indicators)
        is_failure = any(indicator in output for indicator in failure_indicators)
        
        if is_success and not is_failure:
            return True, output
        elif is_failure:
            return False, output
        else:
            return (result.returncode == 0), output
            
    except subprocess.TimeoutExpired:
        return False, "Connection timeout (service may be slow or filtered)"
    except FileNotFoundError:
        return False, f"Error: {nxc_cmd} command not found"
    except Exception as e:
        return False, f"Error: {str(e)}"

def get_example_command(port: int, protocol: str, target: str, username: str, password: str) -> str:
    """Generate example connection command for successful authentication"""
    safe_password = password.replace("'", "'\\''")
    
    commands = {
        21: f"ftp {target}  # then login with {username}",
        22: f"ssh {username}@{target}",
        23: f"telnet {target}  # then login with {username}",
        88: f"nxc smb {target} -u '{username}' -p '{safe_password}' --shares",
        139: f"nxc smb {target} -u '{username}' -p '{safe_password}' --shares",
        389: f"ldapsearch -x -H ldap://{target} -D '{username}' -w '{safe_password}' -b 'dc=domain,dc=com'",
        445: f"nxc smb {target} -u '{username}' -p '{safe_password}' --shares",
        636: f"ldapsearch -x -H ldaps://{target} -D '{username}' -w '{safe_password}' -b 'dc=domain,dc=com'",
        1433: f"nxc mssql {target} -u '{username}' -p '{safe_password}' -q 'SELECT @@version'",
        3306: f"mysql -h {target} -u {username} -p'{safe_password}'",
        3389: f"xfreerdp /u:{username} /p:'{safe_password}' /v:{target} /cert:ignore",
        5432: f"psql -h {target} -U {username} -d postgres",
        5900: f"vncviewer {target}:5900  # Password: {safe_password}",
        5985: f"evil-winrm -i {target} -u '{username}' -p '{safe_password}'",
        5986: f"evil-winrm -i {target} -u '{username}' -p '{safe_password}' -S",
        6379: f"redis-cli -h {target} -a '{safe_password}'",
        27017: f"mongosh mongodb://{username}:{safe_password}@{target}:27017",
    }
    return commands.get(port, f"# Connect to {target}:{port} with {username}")

def print_test_result(port: int, protocol_name: str, success: bool, output: str, 
                     target: str = "", username: str = "", password: str = ""):
    """Print formatted test result"""
    if success:
        print(f"{Colors.OKGREEN}[✓] SUCCESS{Colors.ENDC} - Port {Colors.BOLD}{port}{Colors.ENDC} ({protocol_name})")
        print(f"{Colors.OKCYAN}    └─ Credentials are valid!{Colors.ENDC}")
        if '(Pwn3d!)' in output:
            print(f"{Colors.WARNING}    └─ {Colors.BOLD}⚠ ADMIN ACCESS DETECTED!{Colors.ENDC}")
        if target and username and password:
            example_cmd = get_example_command(port, protocol_name, target, username, password)
            print(f"{Colors.OKBLUE}    └─ Example: {Colors.ENDC}{example_cmd}")
    else:
        print(f"{Colors.FAIL}[✗] FAILED{Colors.ENDC}  - Port {Colors.BOLD}{port}{Colors.ENDC} ({protocol_name})")
        if "timeout" in output.lower():
            print(f"{Colors.WARNING}    └─ Connection timeout{Colors.ENDC}")
        elif "connection" in output.lower() or "refused" in output.lower():
            print(f"{Colors.WARNING}    └─ Connection error (port may be filtered/closed){Colors.ENDC}")
        elif "logon_failure" in output.lower() or "invalid credentials" in output.lower():
            print(f"{Colors.WARNING}    └─ Invalid credentials{Colors.ENDC}")

def main():
    parser = argparse.ArgumentParser(
        description='Test credentials across multiple protocols using NetExec',
        epilog='Example: ./locksmith.py -t 10.10.10.11 -u "admin" -p "password" -ports 22,445,3389',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target IP address or hostname')
    parser.add_argument('-u', '--username', required=True, help='Username to test')
    parser.add_argument('-p', '--password', required=True, help='Password to test')
    parser.add_argument('-ports', '--ports', required=True, help='Comma-separated ports (e.g., 22,445,3389)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output (show NetExec output)')
    parser.add_argument('-d', '--domain', help='Domain name (for SMB/LDAP authentication)', default='.')
    
    args = parser.parse_args()
    
    print_banner()
    
    if not validate_target(args.target):
        print(f"{Colors.FAIL}[!] Invalid target specified!{Colors.ENDC}")
        sys.exit(1)
    
    nxc_cmd = check_dependencies()
    ports = parse_ports(args.ports)
    supported_ports = get_supported_ports(ports)
    
    if not supported_ports:
        print(f"{Colors.FAIL}[!] No supported ports to test!{Colors.ENDC}")
        sys.exit(1)
    
    print(f"{Colors.BOLD}[*] Test Configuration:{Colors.ENDC}")
    print(f"    Target:   {Colors.OKCYAN}{args.target}{Colors.ENDC}")
    print(f"    Username: {Colors.OKCYAN}{args.username}{Colors.ENDC}")
    print(f"    Password: {Colors.OKCYAN}{'*' * min(len(args.password), 12)}{Colors.ENDC}")
    if args.domain and args.domain != '.':
        print(f"    Domain:   {Colors.OKCYAN}{args.domain}{Colors.ENDC}")
    print(f"    Ports:    {Colors.OKCYAN}{', '.join(map(str, supported_ports))}{Colors.ENDC}")
    print()
    print(f"{Colors.BOLD}[*] Starting credential tests...{Colors.ENDC}")
    print(f"{Colors.BOLD}{'=' * 60}{Colors.ENDC}\n")
    
    successful_ports = []
    failed_ports = []
    admin_access = []
    
    for port in supported_ports:
        protocol_info = PORT_PROTOCOLS[port]
        protocol_name = protocol_info['name']
        print(f"{Colors.OKBLUE}[*] Testing Port {port} ({protocol_name})...{Colors.ENDC}")
        
        success, output = test_credential(
            nxc_cmd, args.target, args.username, args.password, port, protocol_info['protocol']
        )
        
        print_test_result(port, protocol_name, success, output, args.target, args.username, args.password)
        
        if args.verbose and output:
            print(f"{Colors.WARNING}    [Verbose Output]:{Colors.ENDC}")
            for line in output.split('\n')[:10]:
                if line.strip():
                    print(f"    {line}")
        print()
        
        if success:
            successful_ports.append((port, protocol_name))
            if '(Pwn3d!)' in output:
                admin_access.append((port, protocol_name))
        else:
            failed_ports.append((port, protocol_name))
    
    print(f"{Colors.BOLD}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.BOLD}[*] Test Summary:{Colors.ENDC}\n")
    
    if successful_ports:
        print(f"{Colors.OKGREEN}{Colors.BOLD}✓ SUCCESSFUL AUTHENTICATIONS:{Colors.ENDC}")
        for port, name in successful_ports:
            admin_marker = " (ADMIN)" if (port, name) in admin_access else ""
            print(f"  {Colors.OKGREEN}→ Port {port} ({name}){admin_marker}{Colors.ENDC}")
        print()
    
    if admin_access:
        print(f"{Colors.WARNING}{Colors.BOLD}⚠ ADMIN ACCESS DETECTED ON:{Colors.ENDC}")
        for port, name in admin_access:
            print(f"  {Colors.WARNING}→ Port {port} ({name}){Colors.ENDC}")
        print()
    
    if failed_ports:
        print(f"{Colors.FAIL}{Colors.BOLD}✗ FAILED AUTHENTICATIONS:{Colors.ENDC}")
        for port, name in failed_ports:
            print(f"  {Colors.FAIL}→ Port {port} ({name}){Colors.ENDC}")
        print()
    
    total = len(supported_ports)
    success_count = len(successful_ports)
    fail_count = len(failed_ports)
    
    print(f"{Colors.BOLD}[*] Statistics:{Colors.ENDC}")
    print(f"    Total Tests:  {total}")
    print(f"    {Colors.OKGREEN}Successful:   {success_count}{Colors.ENDC}")
    print(f"    {Colors.FAIL}Failed:       {fail_count}{Colors.ENDC}")
    if total > 0:
        print(f"    Success Rate: {Colors.OKCYAN}{(success_count/total*100):.1f}%{Colors.ENDC}")
    print()
    
    if successful_ports:
        print(f"{Colors.OKGREEN}{Colors.BOLD}[+] Credentials are VALID on {success_count} service(s)!{Colors.ENDC}")
        if admin_access:
            print(f"{Colors.WARNING}{Colors.BOLD}[!] ADMIN ACCESS on {len(admin_access)} service(s)!{Colors.ENDC}")
    else:
        print(f"{Colors.FAIL}[!] Credentials failed on all tested services.{Colors.ENDC}")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Interrupted by user.{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.FAIL}[!] Unexpected error: {str(e)}{Colors.ENDC}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
