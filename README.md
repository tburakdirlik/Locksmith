# 🔐 LOCKSMITH - Multi-Protocol Credential Testing Tool

LockSmith is a high-efficiency authentication testing tool designed for penetration testers to eliminate manual repetition and accelerate the transition from discovery to access. Instead of manually testing discovered credentials across various services, LockSmith automates the process by parsing Nmap scan results and instantly performing credential validation across all open attack surfaces and also it shows post exploitation commands after successfull authebtications. Acting as a powerful wrapper for NetExec (nxc), it ensures that no service is left unchecked while saving critical time during internal tests and OSCP-style exams.

## 🎯 Features

- Multi-protocol support (SMB, SSH, FTP, RDP, WinRM, MSSQL, MySQL, LDAP)
- Color-coded output for easy analysis
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

## 🛠️ Installation & Setup

```bash
git clone https://github.com/tburakdirlik/Locksmith.git
cd locksmith
chmod +x locksmith.py
```

## 🚀 Usage

```bash
# Recommended usage
# Scan open ports with nmap then parse to locksmith
nmap -p- -T4 192.168.1.100 --open
python3 locksmith.py -t 10.10.10.11 -u "user" -p "pass" -ports 22,445,3389

# Direct execution
./locksmith.py -t 192.168.1.100 -u "admin" -p "password" -ports 445,3389,5985

# Verbose output
./locksmith.py -t 192.168.1.10 -u "user" -p "pass" -ports 445,3389 -v

# Test Multiple Targets
for ip in $(cat targets.txt); do
    ./locksmith.py -t $ip -u "admin" -p "password" -ports 445,3389
done

# Save Results
./locksmith.py -t TARGET -u USER -p PASS -ports 445,3389 | tee results.txt

```

## 📊 Output Example

```
[✓] SUCCESS - Port 389 (LDAP)
    └─ Credentials are valid!
    └─ Example: ldapsearch -x -H ldap://192.168.243.21 -D 'Craig.Carr' -w 'Spring2023' -b 'dc=domain,dc=com'

[✓] SUCCESS - Port 445 (SMB)
    └─ Credentials are valid!
    └─ Example: nxc smb 192.168.243.21 -u 'Craig.Carr' -p 'Spring2023' --shares

[✓] SUCCESS - Port 3389 (RDP)
    └─ Credentials are valid!
    └─ Example: xfreerdp /u:Craig.Carr /p:Spring2023 /v:192.168.243.21 /cert:ignore

[✗] FAILED  - Port 5985 (WinRM)
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

## 📸 Screenshots

![Locksmith Usage Example 1](https://raw.githubusercontent.com/tburakdirlik/Locksmith/refs/heads/main/ss-1.png)

![Locksmith Usage Example 2](https://raw.githubusercontent.com/tburakdirlik/Locksmith/refs/heads/main/ss-2.png)

## Next Updates

Anonymous Login - Guest Access - Default Credentials

---

**Made for Penetration Testing** 🎓
