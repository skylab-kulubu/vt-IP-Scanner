import requests
import json
import argparse
import os

parser = argparse.ArgumentParser(description="This is a simple script to get the last analysis stats of an IP address from VirusTotal")
# IP Address File
subparser = parser.add_subparsers(dest="mode")

file_parser = subparser.add_parser("file", help="File mode")
file_parser.add_argument("-f", "--file", help="File with IP addresses", required=True)

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

if not headers["X-Apikey"]:
    raise ValueError("API key not found. Please set the VT_API_KEY environment variable.")

def is_ytu(data):
    if "Yildiz Teknik University" in data["data"]["attributes"]["whois"]:
        print("\033[94mThis IP belongs to Yildiz Teknik University\033[0m")

def is_malicious(data):
    if (data["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0 or data["data"]["attributes"]["last_analysis_stats"]["suspicious"] > 0) and  ((data["data"]["attributes"]["last_analysis_stats"]["harmless"] > 20) and not (data["data"]["attributes"]["last_analysis_stats"]["malicious"] > 20 or data["data"]["attributes"]["last_analysis_stats"]["suspicious"] > 20)):
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

