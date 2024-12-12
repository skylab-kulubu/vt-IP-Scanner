# vt-IP-Scanner
Virustotal API Scanner

```
usage: main.py [-h] {file,single,upload} ...

This is a simple script to get the last analysis stats of an IP address from VirusTotal

positional arguments:
  {file,single,upload}
    file                File mode
    single              Single mode
    upload              Upload mode

options:
  -h, --help            show this help message and exit
```

## Mass IP Scan
```
usage: main.py file [-h] -f FILE

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  File with IP addresses
```

## Single IP Scan
```
usage: main.py single [-h] -i IP

options:
  -h, --help      show this help message and exit
  -i IP, --ip IP  Single IP address
```

## File Scan
```
usage: main.py upload [-h] -u UPLOAD

options:
  -h, --help            show this help message and exit
  -u UPLOAD, --upload UPLOAD
                        File to upload
```

## CLI Cheat Sheet

### Setup (Sudo Required)
```bash
bash setup.sh
```

### Data Search

```bash
python3 main.py file -f ip_addresses.txt| tee [-a] report
```

```bash
cat report| grep -i "belongs" -B 1
```

```bash
cat report| grep -i "belongs" -B 2
```

```bash
cat report| grep -i "not malicious" -B 1
```

```bash
cat report| grep -i "not malicious" -B 2
```

#### Extract IPv4 Addresses
```bash
grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"
```

# Also Check
- https://api.ipthreat.net/swagger/index.html
- https://talosintelligence.com/
- https://www.abuseipdb.com/
- https://docs.abuseipdb.com/#introduction