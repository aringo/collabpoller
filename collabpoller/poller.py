import os
import json
import secrets
import hashlib
import base64
import requests
import time
import shutil
import argparse
from datetime import datetime

_ALPHA = "abcdefghijklmnopqrstuvwxyz0123456789"
_ZS = {c: i for i, c in enumerate(_ALPHA)}

_DNS_QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}


def _to_base36(hash_bytes: bytes) -> str:
    num = int.from_bytes(hash_bytes, "big")
    if num == 0:
        return _ALPHA[0]
    digits = []
    while num > 0:
        digits.append(_ALPHA[num % 36])
        num //= 36
    return "".join(reversed(digits))


def _alpha_checksum(s: str) -> str:
    return _ALPHA[sum(ord(c) for c in s) % 36]


def _iv_checksum(b1: int, b2: int) -> str:
    return _ALPHA[(b1 + b2) % 36]


def _fingerprint(key: bytes) -> str:
    h = hashlib.sha1(key).digest()
    enc = _to_base36(h)[:20]
    p1, p2 = enc[:10], enc[10:]
    return p1 + _alpha_checksum(p1) + p2 + _alpha_checksum(p2)


def _stream_cipher(iv: list, plaintext: str) -> str:
    state = list(iv)
    out = []
    for i, c in enumerate(plaintext):
        t = i % 2
        enc = _ALPHA[(_ZS[c] + _ZS[chr(state[t])]) % 36]
        state[t] = ord(enc)
        out.append(enc)
    return "".join(out)


def generate_subdomain_label(key: bytes, counter: int = 1, label: str = "") -> str:
    iv = [ord(secrets.choice(_ALPHA)), ord(secrets.choice(_ALPHA))]
    fp = _fingerprint(key)
    content = fp + format(counter, "x") + "g" + label + "z"
    enc = _stream_cipher(iv, content)
    return chr(iv[0]) + chr(iv[1]) + _iv_checksum(iv[0], iv[1]) + enc


def new_collaborator_client() -> tuple:
    key = secrets.token_bytes(32)
    biid = base64.b64encode(key).decode()
    return biid, key


def biid_from_key(key: bytes) -> str:
    return base64.b64encode(key).decode()


def key_from_biid(biid: str) -> bytes:
    return base64.b64decode(biid)


def base64_decode(data: str) -> str:
    return base64.b64decode(data).decode("utf-8", errors="replace")


def _fmt_time(ts: str) -> str:
    try:
        return datetime.fromtimestamp(int(ts) / 1000).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts


def _sep(title: str = "") -> str:
    cols = shutil.get_terminal_size().columns
    if title:
        side = max(2, (cols - len(title) - 2) // 2)
        return "─" * side + " " + title + " " + "─" * side
    return "─" * cols


color_index = 0
color_reset = "\033[0m"
color_codes = ["\033[92m", "\033[93m", "\033[94m", "\033[95m", "\033[96m"]


def print_cycle_color(text):
    global color_index
    color = color_codes[color_index]
    print(color + text + color_reset)
    color_index = (color_index + 1) % len(color_codes)


class CollaboratorPoller:
    def __init__(self, config_file=None, quiet_missing_config: bool = False):
        self.config_file = config_file
        self.config = self.load_config()
        self.server_domain = ""
        self.output_file = ""
        self.poll_interval = 60
        self._key = None
        self._biid = None
        self._counter = 1
        if not self.config:
            if not quiet_missing_config:
                print("Configuration file not found or invalid. Please set the correct path.")
            return

        self.server_domain = self.config.get("subdomain", "")
        self.output_file = self.config.get("output", "")
        self.poll_interval = self.config.get("poll_interval", 60)

        client_cfg = self.config.get("client")
        if client_cfg and client_cfg.get("key"):
            self._key = base64.b64decode(client_cfg["key"])
            self._biid = biid_from_key(self._key)
            self._counter = client_cfg.get("counter", 1)
        else:
            if self.server_domain:
                self._auto_init()

    def _auto_init(self):
        key = secrets.token_bytes(32)
        biid = biid_from_key(key)
        self._key = key
        self._biid = biid
        self._counter = 1
        self.config["client"] = {
            "key": base64.b64encode(key).decode(),
            "counter": 1,
        }
        self._save_config()
        print(f"[collabpoller] New unique client key generated and saved to config.")
        print(f"[collabpoller] BIID: {biid}")

    def init(self, subdomain: str = "", force: bool = False) -> dict:
        if not self.config:
            self.create_default_config(subdomain=subdomain)
            print(f"[collabpoller] Created default config at {self.config_path()}")
            if not subdomain:
                print("[collabpoller] Set your collaborator domain in the config, or rerun:")
                print("  collabpoller --init --subdomain <your-collaborator-domain>")
                return {}
            print("[collabpoller] Using subdomain provided on the command line.")

        existing = self.config.get("client", {}).get("key")
        if existing and not force:
            print(
                "[collabpoller] A client key already exists in this config.\n"
                "  Use --init --force to rotate it (you will lose access to\n"
                "  interactions tied to the old key).\n"
                f"  Existing BIID: {biid_from_key(base64.b64decode(existing))}"
            )
            return {"biid": biid_from_key(base64.b64decode(existing)), "key": existing}

        if subdomain:
            self.server_domain = subdomain
            self.config["subdomain"] = subdomain

        if not self.server_domain:
            print("Error: 'subdomain' must be set in config or passed via --subdomain.")
            return {}

        key = secrets.token_bytes(32)
        biid = biid_from_key(key)
        self._key = key
        self._biid = biid
        self._counter = 1
        self.config["client"] = {
            "key": base64.b64encode(key).decode(),
            "counter": 1,
        }
        self._save_config()

        if force and existing:
            print("[collabpoller] Client key rotated.")
        else:
            print("[collabpoller] Client initialised.")
        print(f"  BIID: {biid}")
        print(f"  Key:  {base64.b64encode(key).decode()}")
        return {"biid": biid, "key": base64.b64encode(key).decode()}

    def config_path(self):
        return self.config_file or os.path.join(
            os.path.expanduser("~"), ".config", "collaborator_poller", "config.json"
        )

    def load_config(self):
        filename = self.config_path()
        if os.path.exists(filename):
            try:
                with open(filename) as f:
                    return json.load(f)
            except (OSError, json.JSONDecodeError):
                return None
        return None

    def create_default_config(self, subdomain: str = "", overwrite: bool = False):
        filename = self.config_path()
        if os.path.exists(filename) and not overwrite:
            self.config = self.load_config()
            return self.config

        self.config = {
            "poll_interval": 45,
            "subdomain": subdomain,
            "output": "",
        }
        self.server_domain = subdomain
        self.output_file = ""
        self.poll_interval = 45
        self._key = None
        self._biid = None
        self._counter = 1
        self._save_config()
        return self.config

    def _save_config(self):
        filename = self.config_path()
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, "w") as f:
            json.dump(self.config, f, indent=4)

    def new_client(self, num_payloads: int = 10, save: bool = False) -> dict:
        if not self.server_domain:
            print("Error: 'subdomain' must be set in config before generating a client.")
            return {}

        biid, key = new_collaborator_client()
        samples = [
            f"{generate_subdomain_label(key, i)}.{self.server_domain}"
            for i in range(1, num_payloads + 1)
        ]
        result = {
            "biid": biid,
            "key": base64.b64encode(key).decode(),
            "sample_payloads": samples,
        }

        if save:
            self._key = key
            self._biid = biid
            self._counter = num_payloads + 1
            self.config["client"] = {
                "key": result["key"],
                "counter": self._counter,
            }
            self._save_config()
            print(f"Client saved to config. BIID: {biid}")

        return result

    def gen_payload(self) -> str:
        if self._key is None:
            return ""
        label = generate_subdomain_label(self._key, self._counter)
        self._counter += 1
        if self.config and "client" in self.config:
            self.config["client"]["counter"] = self._counter
            self._save_config()
        return f"{label}.{self.server_domain}"

    def poll_collab(self, biid: str):
        url = f"http://polling.{self.server_domain}/burpresults"
        try:
            response = requests.get(url, params={"biid": biid}, timeout=15)
            if response.status_code == 200:
                json_data = response.json()
                if "responses" in json_data:
                    self.parse_collab_response(json_data)
        except requests.RequestException as e:
            print(f"Poll error: {e}")

    def parse_collab_response(self, response_json):
        for response in response_json.get("responses", []):
            if "protocol" not in response:
                continue
            if self.output_file:
                self.log_write(json.dumps(response))

            protocol = response["protocol"].lower()
            ts = _fmt_time(response.get("time", ""))
            client = response.get("client", "")
            port = response.get("clientPort", "")
            iid = response.get("interactionId", "")
            data = response.get("data", {})

            if protocol in ("http", "https"):
                self._print_http(protocol, ts, client, port, iid, data)
            elif protocol == "dns":
                self._print_dns(ts, client, port, iid, data)
            elif protocol in ("smtp", "smtps"):
                self._print_smtp(protocol, ts, client, port, iid, data)
            else:
                print_cycle_color(
                    f"\n{_sep()}\n{ts}: {protocol.upper()} from {client}:{port}"
                    + (f"  [{iid}]" if iid else "")
                )

    def _print_http(self, protocol, ts, client, port, iid, data):
        header = f"{ts}: {protocol.upper()} from {client}:{port}"
        if iid:
            header += f"  [{iid}]"
        parts = [f"\n{_sep()}", header]

        req_b64 = data.get("request", "")
        resp_b64 = data.get("response", "")

        if req_b64:
            try:
                parts.append(_sep("REQUEST"))
                parts.append(base64_decode(req_b64).strip())
            except Exception:
                parts.append("<could not decode request>")

        if resp_b64:
            try:
                parts.append(_sep("RESPONSE"))
                parts.append(base64_decode(resp_b64).strip())
            except Exception:
                pass

        print_cycle_color("\n".join(parts))

    def _print_dns(self, ts, client, port, iid, data):
        subdomain = data.get("subDomain", "")
        qtype_raw = data.get("queryType", "")
        try:
            qtype = _DNS_QTYPES.get(int(qtype_raw), str(qtype_raw))
        except (ValueError, TypeError):
            qtype = str(qtype_raw)

        header = f"{ts}: DNS {qtype} query for {subdomain} from {client}:{port}"
        if iid:
            header += f"  [{iid}]"

        raw_b64 = data.get("rawQuery", "")
        extra = ""
        if raw_b64:
            try:
                extra = f"\n  Raw query: {len(base64.b64decode(raw_b64))} bytes"
            except Exception:
                pass

        print_cycle_color(f"\n{_sep()}\n{header}{extra}")

    def _print_smtp(self, protocol, ts, client, port, iid, data):
        header = f"{ts}: {protocol.upper()} from {client}:{port}"
        if iid:
            header += f"  [{iid}]"
        parts = [f"\n{_sep()}", header]

        sender = data.get("sender", "")
        recipients = data.get("recipients", [])
        message = data.get("message", "")
        conversation = data.get("conversation", "")

        if sender:
            parts.append(f"  From: {sender}")
        if recipients:
            to_str = ", ".join(recipients) if isinstance(recipients, list) else str(recipients)
            parts.append(f"  To:   {to_str}")

        if message:
            parts.append(_sep("MESSAGE"))
            parts.append(message.strip())
        elif conversation:
            parts.append(_sep("CONVERSATION"))
            parts.append(conversation.strip())

        print_cycle_color("\n".join(parts))

    def poll(self):
        if self._biid:
            self.poll_collab(self._biid)

    def start_polling(self):
        print_cycle_color(f"Checking for requests every: {self.poll_interval} seconds")
        while True:
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"\r{current_time}: polling", end="", flush=True)
            self.poll()
            time.sleep(self.poll_interval)

    def log_write(self, log: str):
        with open(self.output_file, "a") as f:
            f.write(log + "\n")


def main():
    parser = argparse.ArgumentParser(description="Collaborator Poller")
    parser.add_argument("--config", type=str, help="Path to the configuration file")
    parser.add_argument("--payload", action="store_true", help="Output a domain payload to use")
    parser.add_argument("--check", action="store_true", help="Single check for interactions")
    parser.add_argument("--poll", action="store_true", help="Continuously poll for interactions")
    parser.add_argument(
        "--new-client",
        action="store_true",
        help="Generate a new collaborator client (no Burp required). "
             "Use --save to persist to config.",
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="Save generated client key to config (use with --new-client)",
    )
    parser.add_argument(
        "--num-payloads",
        type=int,
        default=10,
        help="Number of sample payloads to generate with --new-client (default: 10)",
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help="Generate a unique client key for this user and save it to config. "
             "Safe to run multiple times — will not overwrite without --force.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="With --init: rotate (overwrite) an existing client key.",
    )
    parser.add_argument(
        "--subdomain",
        type=str,
        default="",
        help="Set or override the collaborator server domain. "
             "With --init, this also bootstraps a new config on first run.",
    )
    args = parser.parse_args()

    poller = CollaboratorPoller(
        config_file=args.config,
        quiet_missing_config=args.init,
    )

    if args.init:
        poller.init(subdomain=args.subdomain, force=args.force)
        return

    if args.new_client:
        result = poller.new_client(num_payloads=args.num_payloads, save=args.save)
        if result:
            print(f"\nBIID:  {result['biid']}")
            print(f"Key:   {result['key']}")
            print("\nSample payloads:")
            for p in result["sample_payloads"]:
                print(f"  {p}")
            if not args.save:
                print(
                    "\nTip: run with --save to persist this client to your config "
                    "so --payload, --check and --poll all use it automatically."
                )
        return

    if args.payload:
        print_cycle_color(f"Generated Payload: {poller.gen_payload()}")

    if args.check:
        poller.poll()

    if args.poll:
        poller.start_polling()


if __name__ == "__main__":
    main()
