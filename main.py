import requests
import json
import argparse
import os
import re


parser = argparse.ArgumentParser(description="This is a simple script to get the last analysis stats of an IP address from VirusTotal")
# IP Address File
subparser = parser.add_subparsers(dest="mode")

file_parser = subparser.add_parser("file", help="File mode")
file_parser.add_argument("-f", "--file", help="File with IP addresses", required=True)
file_parser.add_argument("-p","--parse", help="Parse file for IP addresses", action="store_true")
# Single IP Address
single_parser = subparser.add_parser("single", help="Single mode")
single_parser.add_argument("-i", "--ip", help="Single IP address", required=True)

# File upload
upload_parser = subparser.add_parser("upload", help="Upload mode")
upload_parser.add_argument("-u", "--upload", help="File to upload", required=True)

args = parser.parse_args()

headers = {
    "accept": "application/json",
    "X-Apikey": os.getenv("VT_API_KEY")
}


def extract_ipv4_addresses(file_path:str):
    ipv4_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    with open(file_path, 'r') as file:
        content = file.read()
    return ipv4_pattern.findall(content)



if not headers["X-Apikey"]:
    raise ValueError("API key not found. Please set the VT_API_KEY environment variable.")

def check_whois(data,x:str,y:str=None):
    if y ==None: y=x
    whois = data["data"]["attributes"]["whois"]
    try:    
        if x.lower() in whois.lower():
            print(f"\033[94mThis IP belongs to {y}\033[0m")
    except KeyError:
        print(f"\033[91mWhois information not found for {x}\033[0m")
        
def is_ytu(data):
    check_whois(data,"yildiz","YTÜ")
    
def is_google(data):
    check_whois(data,"google","Google")

def is_malicious(data):
    malicious_value = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
    suspicious_value = data["data"]["attributes"]["last_analysis_stats"]["suspicious"]
    harmless_value = data["data"]["attributes"]["last_analysis_stats"]["harmless"]
    if (malicious_value > 0 or suspicious_value > 0) and  ((harmless_value > 20) and not (malicious_value > 20 or suspicious_value > 20)):
        print("\033[91m\033[1mThis IP is malicious\033[0m")
    else:
        print("\033[92mThis IP is not malicious\033[0m")

def get_ip_analysis(headers, ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    response = requests.get(url, headers=headers)
    data = json.loads(response.text)
    try:
        last_analysis_statistics = data["data"]["attributes"]["last_analysis_stats"]
    except KeyError:
        if data["error"]["code"] == "QuotaExceededError":
            print("\033[91mQuota exceeded. Please try again later.\033[0m")
            quit()
        else:
            print("\033[91mSomethig went wrong. Please try again later.\033[0m")
            quit()
    print(f"----------------IP: {ip} - {last_analysis_statistics}----------------")
    is_ytu(data)
    is_google(data)
    is_malicious(data)

def check_file_upload(headers, file):
    url = "https://www.virustotal.com/api/v3/files"
    with open(file, "rb") as file:
        files = {"file": file}
        response = requests.post(url, headers=headers, files=files)
        data = json.loads(response.text)

        if response.status_code == 200:
            analysis_id = data["data"]["id"]
            print(f"\033[94mFile uploaded successfully. Analysis ID: {analysis_id}\033[0m")
            check_file_analysis(headers, analysis_id)
        else:
            print("\033[91mError uploading file: \033[0m", data)

def check_file_analysis(headers, analysis_id):
    import time
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    while True:
        response = requests.get(url, headers=headers)
        data = json.loads(response.text)

        if response.status_code == 200:
            status = data["data"]["attributes"]["status"]
            if status == "completed":
                stats = data["data"]["attributes"]["stats"]
                print(f"---------------- Analysis ID: {analysis_id} - Stats: {stats} ----------------")
                if stats["malicious"] > 0:
                    print("\033[91m\033[1mThis file is malicious\033[0m")
                else:
                    print("\033[92mThis file is not malicious\033[0m")
                break
            else:
                print(f"---------------- Analysis in progress... Status: {status} ----------------")
                time.sleep(10)
        else:
            print(f"---------------- Error fetching file analysis: {data} ----------------")
            break


if args.mode == "file":
    if args.parse:
        ips = extract_ipv4_addresses(args.file)
    else:
        with open(args.file, 'r') as file:
            ips = set(file.readlines())
    for ip in ips:
        ip = ip.strip()
        get_ip_analysis(headers, ip)    
elif args.mode=="single":
    get_ip_analysis(headers, args.ip)
elif args.mode=="upload":
    check_file_upload(headers, args.upload)
else:
    print("Please provide either a file with IP addresses or a single IP address.")

