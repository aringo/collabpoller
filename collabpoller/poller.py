import os
import json
import random
import requests
import time
from datetime import datetime
import shutil
import base64
import argparse

class CollaboratorPoller:
    def __init__(self, config_file=None):
        self.config_file = config_file
        self.config = self.load_config()
        if not self.config:
            print("Configuration file not found or invalid. Please set the correct path.")
            return

        self.subdomain = self.config.get("subdomain", "")
        self.output_file = self.config.get("output", "")
        self.poll_interval = self.config.get("poll_interval", 60)
        self.biids = self.config.get("biids", {})
        self.all_subdomains = [subdomain for biid in self.biids.values() for subdomain in biid]

    def load_config(self):
        # Check if config_file is set, otherwise use default path
        if self.config_file:
            filename = self.config_file
        else:
            home_dir = os.path.expanduser("~")
            filename = os.path.join(home_dir, ".config", "collaborator_poller", "config.json")

        if os.path.exists(filename):
            with open(filename) as f:
                return json.load(f)
        else:
            return None


    def gen_payload(self):
        return random.choice(self.all_subdomains)

    def poll_collab(self, bid):
        url = f"http://polling.{self.subdomain}/burpresults?biid={bid}"
        response = requests.get(url)
        if response.status_code == 200:
            json_data = response.json()
            if 'responses' in json_data:
                self.parse_collab_response(json_data)

    def parse_collab_response(self, response_json):
        for response in response_json.get('responses', []):
            if 'protocol' in response:
                if self.output_file:
                    self.log_write(json.dumps(response))
                protocol = response['protocol']
                time = response['time']
                client = response['client']
                port = response['clientPort']
                terminal_line = "\n" + ("-" * shutil.get_terminal_size().columns)
                if 'http' in protocol:
                    if 'data' in response and 'request' in response['data']:
                        try:
                            asterisk_line = "*" * 25
                            http_notify = f"{time}: {protocol.upper()} request from {client}:{port}"
                            decoded_request = base64_decode(response['data']['request'])
                            output = terminal_line + "\n" + http_notify + "\n" + asterisk_line + "\n" + decoded_request
                            print_cycle_color(output)
                        except:
                            pass
                elif response['protocol'] == 'dns':
                    if 'data' in response and 'subDomain' in response['data']:
                        subdomain = response['data']['subDomain']
                        print_cycle_color(f"{terminal_line}\n{time}: {protocol.upper()} request {subdomain} from {client}:{port}")
                else:
                    print_cycle_color(f"{terminal_line}\n{time}: {protocol} request {client}:{port}")

    def poll_all_biids(self):
        for biid in self.biids:
            self.poll_collab(biid)

    def start_polling(self):
        print_cycle_color(f"Checking for requests every: {self.poll_interval} seconds")
        while True:
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"\r{current_time}: polling", end="", flush=True)
            self.poll_all_biids()
            time.sleep(self.poll_interval)

    def log_write(self, log):
        with open(self.output_file, 'a') as f:
            f.write(log + "\n")

# Base64 decode for Burp HTTP 
def base64_decode(data):
    decoded_bytes = base64.b64decode(data)
    return decoded_bytes.decode('utf-8')

# Formatting/colors
def print_terminal_line():
    terminal_width = shutil.get_terminal_size().columns
    print("-" * terminal_width)

def print_asterisk_line():
    print("*" * 25)

color_index = 0
color_reset = '\033[0m'
color_codes = ['\033[92m', '\033[93m', '\033[94m', '\033[95m', '\033[96m']
# GREEN: '\033[92m', YELLOW: '\033[93m', BLUE: '\033[94m', PURPLE: '\033[95m', CYAN: '\033[96m'

def print_cycle_color(text):
    global color_index
    color = color_codes[color_index]
    print(color + text + color_reset)
    color_index = (color_index + 1) % len(color_codes)

def main():
    parser = argparse.ArgumentParser(description='Collaborator Poller')
    parser.add_argument('--config', type=str, help='Path to the configuration file')
    parser.add_argument('--payload', action='store_true', help='Outputs a domain to use')
    parser.add_argument('--check', action='store_true', help='Single check for interactions')
    parser.add_argument('--poll', action='store_true', help='Continues to poll for interactions')
    args = parser.parse_args()

    # Pass config_file argument if provided
    poller = CollaboratorPoller(config_file=args.config)

    if args.payload:
        print_cycle_color(f"Generated Payload: {poller.gen_payload()}")

    if args.check:
        poller.poll_all_biids()

    if args.poll:
        poller.start_polling()

if __name__ == "__main__":
    main()