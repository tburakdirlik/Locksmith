# 🔐 LOCKSMITH - Multi-Protocol Credential Testing Tool

LockSmith is a high-efficiency authentication testing tool designed for penetration testers to eliminate manual repetition and accelerate the transition from discovery to access. Instead of manually testing discovered credentials across various services, LockSmith automates the process by parsing Nmap scan results and instantly performing credential validation across all open attack surfaces. Acting as a powerful wrapper for NetExec (nxc), it ensures that no service is left unchecked while saving critical time during internal assessments and OSCP-style exams.

## 🎯 Features

- Multi-protocol support (SMB, SSH, FTP, RDP, WinRM, MSSQL, MySQL, LDAP)
- Color-coded output for easy analysis
- Admin access detection (Pwn3d!)
- Automatic filtering of unsupported ports
- Example connection commands for successful authentications

## 📋 Requirements

```bash
# Kali Linux (recommended)
sudo apt update
sudo apt install netexec

# Manual installation
pipx install netexec
```

## 🚀 Usage

```bash
# Basic usage
python3 locksmith.py -t 10.10.10.11 -u "user" -p "pass" -ports 22,445,3389

# Direct execution
./locksmith.py -t 192.168.1.100 -u "admin" -p "password" -ports 445,3389,5985

# Verbose output
./locksmith.py -t 192.168.1.10 -u "user" -p "pass" -ports 445,3389 -v
```

## 🔌 Supported Ports

| Port | Protocol | Service |
|------|----------|---------|
| 21 | FTP | File Transfer Protocol |
| 22 | SSH | Secure Shell |
| 88 | Kerberos/SMB | Windows Authentication |
| 139 | NetBIOS/SMB | NetBIOS Session |
| 389 | LDAP | Directory Access |
| 445 | SMB | Server Message Block |
| 636 | LDAPS | LDAP over SSL |
| 1433 | MSSQL | Microsoft SQL Server |
| 3306 | MySQL | MySQL Database |
| 3389 | RDP | Remote Desktop |
| 5432 | PostgreSQL | PostgreSQL Database |
| 5985 | WinRM | Windows Remote Management |
| 5986 | WinRM-HTTPS | WinRM over HTTPS |

## 📊 Output Example

```
[✓] SUCCESS - Port 389 (LDAP)
    └─ Credentials are valid!
    └─ Example: ldapsearch -x -H ldap://192.168.243.21 -D 'Craig.Carr' -w 'Spring2023' -b 'dc=domain,dc=com'

[✓] SUCCESS - Port 445 (SMB)
    └─ Credentials are valid!
    └─ ADMIN ACCESS DETECTED!
    └─ Example: nxc smb 192.168.243.21 -u 'Craig.Carr' -p 'Spring2023' --shares

[✓] SUCCESS - Port 3389 (RDP)
    └─ Credentials are valid!
    └─ Example: xfreerdp /u:Craig.Carr /p:Spring2023 /v:192.168.243.21 /cert:ignore

[✗] FAILED  - Port 5985 (WinRM)
```

## 🎯 Post-Exploitation Commands

### SMB (Port 445)
```bash
# Enumerate shares
nxc smb TARGET -u USER -p PASS --shares

# Execute commands (if Pwn3d!)
nxc smb TARGET -u USER -p PASS -x "whoami"

# Dump SAM (if admin)
nxc smb TARGET -u USER -p PASS --sam
```

### LDAP (Port 389)
```bash
# Enumerate users
ldapsearch -x -H ldap://TARGET -D USER -w PASS -b "dc=domain,dc=com" "(objectClass=user)"
```

### RDP (Port 3389)
```bash
# Connect with clipboard
xfreerdp /u:USER /p:PASS /v:TARGET /cert:ignore +clipboard
```

### WinRM (Port 5985)
```bash
# Interactive shell
evil-winrm -i TARGET -u USER -p PASS
```

### SSH (Port 22)
```bash
# Interactive login
ssh USER@TARGET
```

### FTP (Port 21)
```bash
# Download all files
wget -m ftp://USER:PASS@TARGET
```

### MSSQL (Port 1433)
```bash
# Interactive connection
impacket-mssqlclient USER:PASS@TARGET
```

## 💡 Pro Tips

### Test Multiple Targets
```bash
for ip in $(cat targets.txt); do
    ./locksmith.py -t $ip -u "admin" -p "password" -ports 445,3389
done
```

### Save Results
```bash
./locksmith.py -t TARGET -u USER -p PASS -ports 445,3389 | tee results.txt
```

### Integration with Nmap
```bash
# Scan for open ports
nmap -p- -T4 192.168.1.100 --open

# Test discovered ports
./locksmith.py -t 192.168.1.100 -u "admin" -p "pass" -ports 445,3389,5985
```

## 🔍 Parameters

| Parameter | Description | Required |
|-----------|-------------|----------|
| `-t, --target` | Target IP address | ✅ |
| `-u, --username` | Username to test | ✅ |
| `-p, --password` | Password to test | ✅ |
| `-ports` | Comma-separated port list | ✅ |
| `-v, --verbose` | Show detailed output | ❌ |

## 🐛 Troubleshooting

### NetExec Not Found
```bash
sudo apt install netexec
```

### Permission Denied
```bash
chmod +x locksmith.py
```

### Connection Timeout
- Check firewall rules
- Verify target is online
- Check VPN connection

## 🛡️ Security Notes

⚠️ **WARNING**: Use only for legal penetration testing and educational purposes.

- Only use on systems you have permission to test
- Be aware of account lockout policies
- Avoid excessive authentication attempts

## 📚 Resources

- [NetExec Documentation](https://www.netexec.wiki/)
- [HackTricks](https://book.hacktricks.xyz/)

## 📸 Screenshots

![Locksmith Usage Example 1](https://raw.githubusercontent.com/tburakdirlik/Locksmith/refs/heads/main/ss-1.png)

![Locksmith Usage Example 2](https://raw.githubusercontent.com/tburakdirlik/Locksmith/refs/heads/main/ss-2.png)

## Next Updates

Anonymous Login - Guest Access - Default Credentials

---

**Made for Penetration Testing** 🎓
