# vt-IP-Scanner
Virustotal API Scanner

```
❯ python3 main.py 
usage: main.py [-h] {file,single} ...

This is a simple script to get the last analysis stats of an IP address from VirusTotal

positional arguments:
  {file,single}
    file         File mode
    single       Single mode

options:
  -h, --help     show this help message and exit
```
```
❯ python3 main.py file
usage: main.py file [-h] -f FILE

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  File with IP addresses
```

```
❯ python3 main.py single
usage: main.py single [-h] -i IP

options:
  -h, --help      show this help message and exit
  -i IP, --ip IP  Single IP address
```

## CLI Cheat Sheet

```bash
python3 main.py file -f ip_addresses.txt| tee [-a] report
```

```bash
cat report| grep -i "belongs" -B 1
```

```bash
cat report| grep -i "not malicious" -B 1
```