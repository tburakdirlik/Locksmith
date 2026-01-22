# 🔓 LOCKSMITH - Multi-Protocol Credential Testing Tool

LockSmith is a high-efficiency authentication testing tool designed for penetration testers. It automates credential validation across multiple services by wrapping NetExec, saving critical time during internal tests and security assessments.

## ✨ Features

- **18 different protocols** support
- Color-coded output for easy analysis
- Automatic port filtering
- Admin access detection (Pwn3d!)
- Success rate statistics
- Domain authentication support
- Detailed error reporting

## 📋 Requirements

```bash
# Kali Linux (recommended)
sudo apt update
sudo apt install netexec

# For Telnet testing (optional)
sudo apt install expect
```

## 🛠️ Installation

```bash
git clone https://github.com/tburakdirlik/Locksmith.git
cd Locksmith
chmod +x locksmith.py
```

## 🚀 Usage

### Basic Usage

```bash
# Recommended workflow: Scan with nmap first
nmap -p- -T4 192.168.1.100 --open

# Then test discovered credentials
python3 locksmith.py -t '192.168.1.100' -u 'admin' -p 'password' -ports 445,3389,5985
```

### Examples

```bash
# SSH test
./locksmith.py -t '10.10.10.11' -u 'user' -p 'password123' -ports 22

# Windows services
./locksmith.py -t '192.168.1.100' -u 'admin' -p 'P@ssw0rd!' -ports 445,3389,5985

# Database servers
./locksmith.py -t 'db-server' -u 'sa' -p 'SqlPass!' -ports 1433,3306,5432,27017

# Telnet test
./locksmith.py -t '10.10.10.50' -u 'admin' -p 'admin' -ports 23

# Verbose mode
./locksmith.py -t '192.168.1.10' -u 'user' -p 'pass' -ports 445,3389 -v

# Domain authentication
./locksmith.py -t 'dc.contoso.local' -u 'administrator' -p 'Pass!' -ports 445,389 -d CONTOSO
```

### Batch Operations

```bash
# Multiple targets
for ip in $(cat targets.txt); do
    ./locksmith.py -t "$ip" -u 'admin' -p 'password' -ports 445,3389
done

# Save results
./locksmith.py -t '10.10.10.100' -u 'admin' -p 'pass' -ports 445 | tee results.txt
```

## 📊 Output Example

```
[✓] SUCCESS - Port 445 (SMB)
    └─ Credentials are valid!
    └─ ⚠ ADMIN ACCESS DETECTED!
    └─ Example: nxc smb 192.168.1.100 -u 'admin' -p 'password' --shares

[✗] FAILED  - Port 3389 (RDP)
    └─ Invalid credentials

═══════════════════════════════════════════════════════════
[*] Test Summary:

✓ SUCCESSFUL AUTHENTICATIONS:
  → Port 445 (SMB) (ADMIN)

⚠ ADMIN ACCESS DETECTED ON:
  → Port 445 (SMB)

[*] Statistics:
    Total Tests:  2
    Successful:   1
    Failed:       1
    Success Rate: 50.0%

[+] Credentials are VALID on 1 service(s)!
[!] ADMIN ACCESS on 1 service(s)!
═══════════════════════════════════════════════════════════
```

## 🔌 Supported Protocols

| Port | Protocol | Service |
|------|----------|---------|
| 21 | FTP | File Transfer Protocol |
| 22 | SSH | Secure Shell |
| 23 | Telnet | Telnet (with expect) |
| 88 | Kerberos | Windows Kerberos |
| 139 | NetBIOS | NetBIOS Session |
| 389 | LDAP | Directory Access |
| 445 | SMB | Server Message Block |
| 636 | LDAPS | LDAP over SSL |
| 1433 | MSSQL | Microsoft SQL Server |
| 3306 | MySQL | MySQL Database |
| 3389 | RDP | Remote Desktop |
| 5432 | PostgreSQL | PostgreSQL Database |
| 5900 | VNC | Virtual Network Computing |
| 5985 | WinRM | Windows Remote Management |
| 5986 | WinRM-HTTPS | WinRM over HTTPS |
| 6379 | Redis | Redis Database |
| 27017 | MongoDB | MongoDB NoSQL |

## 📝 Parameters

| Parameter | Short | Description | Required | Example |
|-----------|-------|-------------|----------|---------|
| `--target` | `-t` | Target IP or hostname | ✅ | `'192.168.1.100'` |
| `--username` | `-u` | Username to test | ✅ | `'admin'` |
| `--password` | `-p` | Password to test | ✅ | `'P@ssw0rd123'` |
| `--ports` | `-ports` | Comma-separated port list | ✅ | `22,445,3389` |
| `--verbose` | `-v` | Show detailed output | ❌ | - |
| `--domain` | `-d` | Domain name (for AD) | ❌ | `'CONTOSO'` |

## 💡 Usage Tips

- **Always use single quotes**: `-u 'user' -p 'password'`
- **Special characters**: Automatically escaped
- **Domain format**: `-u 'DOMAIN\username'` or use `-d` parameter
- **Ports parameter**: No dashes: `-ports 22,445`

## 🎯 Real-World Scenarios

### Windows Domain Controller
```bash
./locksmith.py -t 'dc.company.local' -u 'admin' -p 'Pass!' -ports 445,389,636,3389,5985
```

### Linux Web Server
```bash
./locksmith.py -t 'web-server' -u 'webadmin' -p 'WebPass' -ports 21,22,23,3306
```

### Database Server
```bash
./locksmith.py -t 'db-server' -u 'sa' -p 'SqlPass' -ports 1433,3306,5432,27017
```

### Pentest Workflow
```bash
# 1. Port scan
nmap -p- -T4 --open 10.10.10.0/24 -oG ports.txt

# 2. Extract IPs
grep "Up" ports.txt | cut -d " " -f 2 > targets.txt

# 3. Test credentials
for ip in $(cat targets.txt); do
    ./locksmith.py -t "$ip" -u 'admin' -p 'password' -ports 22,23,445,3389
done
```

## 🛠️ Troubleshooting

### NetExec Not Found
```bash
# Check installation
which nxc

# Install
sudo apt install netexec
```

### Permission Denied
```bash
chmod +x locksmith.py
```

### Connection Timeout
```bash
# Check host
ping 10.10.10.10

# Check port
nmap -p 445 10.10.10.10
```

### Telnet Test Not Working
```bash
# Install expect
sudo apt install expect
```


### Legal Use Cases
- ✅ Authorized penetration testing with written permission
- ✅ Your own systems and networks
- ✅ Educational purposes in lab environments
- ✅ OSCP/certification exam labs


### Account Lockout Warning
⚠️ **Multiple failed authentication attempts can trigger account lockouts!**

- Default Windows lockout: 5 failed attempts
- Be cautious when testing multiple credentials
- Use `--verbose` to monitor detailed responses


## ⚖️ Disclaimer

This tool is provided for **educational and authorized testing purposes only**. The authors and contributors are not responsible for any misuse or damage caused by this tool. Unauthorized access to computer systems is illegal.

---
