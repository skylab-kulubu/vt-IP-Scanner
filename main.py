import requests
import json
import argparse

parser = argparse.ArgumentParser(description="This is a simple script to get the last analysis stats of an IP address from VirusTotal")
# IP Address File
subparser = parser.add_subparsers(dest="mode")

file_parser = subparser.add_parser("file", help="File mode")
file_parser.add_argument("-f", "--file", help="File with IP addresses", required=True)

# Single IP Address
single_parser = subparser.add_parser("single", help="Single mode")
single_parser.add_argument("-i", "--ip", help="Single IP address", required=True)

args = parser.parse_args()

headers = {
    "accept": "application/json",
    "X-Apikey": "e313477a3fd0ef5dee51456071dc12430270ea5e08c6dae4198c9831e637b5b3"
}

def is_ytu(data):
    if "Yildiz Teknik University" in data["data"]["attributes"]["whois"]:
        print("\033[94mThis IP belongs to Yildiz Teknik University\033[0m")

def is_malicious(data):
    if data["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0 or data["data"]["attributes"]["last_analysis_stats"]["suspicious"] > 0:
        print("\033[91m\033[1mThis IP is malicious\033[0m")
    else:
        print("\033[92mThis IP is not malicious\033[0m")

def get_ip_analysis(headers, ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    response = requests.get(url, headers=headers)
    data = json.loads(response.text)
    print(f"----------------IP: {ip} - {data['data']['attributes']['last_analysis_stats']}----------------")
    is_ytu(data)
    is_malicious(data)

if args.mode == "file":
    with open(args.file, 'r') as file:
        ips = set(file.readlines())
        for ip in ips:
            ip = ip.strip()
            get_ip_analysis(headers, ip)
elif args.mode=="single":
    get_ip_analysis(headers, args.ip)
else:
    print("Please provide either a file with IP addresses or a single IP address.")