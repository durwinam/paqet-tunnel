#!/usr/bin/env python3
import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

HOST = '0.0.0.0'
PORT = int(os.environ.get('PAQET_PANEL_PORT', '6102'))
PAQET_DIR = '/opt/paqet'
STATE_DIR = os.path.join(PAQET_DIR, 'panel')
STATE_FILE = os.path.join(STATE_DIR, 'auth.json')
META_FILE = os.path.join(STATE_DIR, 'tunnels.json')
STATIC_DIR = os.path.join(os.path.dirname(__file__), 'static')
ASSET_DIR = os.path.join(STATIC_DIR, 'assets')

os.makedirs(STATE_DIR, exist_ok=True)


def read_json(path, default):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return default


def write_json(path, value, mode=0o600):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    os.chmod(path, mode)


def load_auth():
    data = read_json(STATE_FILE, None)
    if isinstance(data, dict) and data.get('username') and data.get('password_sha256'):
        return data
    pw = secrets.token_urlsafe(12)
    data = {
        'username': 'admin',
        'password_sha256': hashlib.sha256(pw.encode()).hexdigest(),
        'generated_password': pw,
    }
    write_json(STATE_FILE, data)
    return data


AUTH = load_auth()
SESSIONS = set()


def run(cmd, timeout=8, input_text=None):
    try:
        p = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=timeout, input=input_text,
        )
        return p.returncode, p.stdout.strip()
    except Exception as e:
        return 1, str(e)


def valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def valid_port(value):
    try:
        n = int(value)
        return 1 <= n <= 65535
    except Exception:
        return False


def valid_ports(value):
    parts = [p.strip() for p in str(value).split(',') if p.strip()]
    return bool(parts) and all(valid_port(p) for p in parts)


def get_default_interface():
    rc, out = run(['ip', 'route'], 3)
    for line in out.splitlines():
        m = re.match(r'\s*default\s+.*\sdev\s+(\S+)', line)
        if m:
            return m.group(1)
    return ''


def get_local_ip(interface):
    if not interface:
        return ''
    rc, out = run(['ip', '-4', 'addr', 'show', interface], 3)
    m = re.search(r'inet\s+(\d+(?:\.\d+){3})/', out)
    return m.group(1) if m else ''


def get_gateway_ip():
    rc, out = run(['ip', 'route'], 3)
    for line in out.splitlines():
        m = re.match(r'\s*default\s+via\s+(\S+)', line)
        if m:
            return m.group(1)
    return ''


def get_gateway_mac():
    gateway = get_gateway_ip()
    if not gateway:
        return ''
    run(['ping', '-c', '1', '-W', '1', gateway], 3)
    rc, out = run(['ip', 'neigh', 'show', gateway], 3)
    m = re.search(r'([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', out)
    if m:
        return m.group(0)
    return ''


def get_public_ip():
    for url in ('https://api.ipify.org', 'https://ifconfig.me', 'https://icanhazip.com'):
        rc, out = run(['curl', '-4', '-fsS', '--max-time', '3', url], 5)
        if rc == 0 and valid_ip(out.strip()):
            return out.strip()
    return get_local_ip(get_default_interface())


def network_info():
    iface = get_default_interface()
    local = get_local_ip(iface)
    public = get_public_ip()
    mac = get_gateway_mac()
    return {
        'interface': iface,
        'local_ip': local,
        'public_ip': public,
        'gateway_mac': mac,
        'gateway_ip': get_gateway_ip(),
    }


def save_iptables():
    if shutil.which('iptables-save'):
        if os.path.isdir('/etc/iptables'):
            rc, out = run(['iptables-save'], 8)
            if rc == 0:
                try:
                    with open('/etc/iptables/rules.v4', 'w', encoding='utf-8') as f:
                        f.write(out + '\n')
                except Exception:
                    pass


def server_firewall(port):
    cmds = [
        ['iptables', '-t', 'raw', '-D', 'PREROUTING', '-p', 'tcp', '--dport', str(port), '-j', 'NOTRACK'],
        ['iptables', '-t', 'raw', '-D', 'OUTPUT', '-p', 'tcp', '--sport', str(port), '-j', 'NOTRACK'],
        ['iptables', '-t', 'mangle', '-D', 'OUTPUT', '-p', 'tcp', '--sport', str(port), '--tcp-flags', 'RST', 'RST', '-j', 'DROP'],
        ['iptables', '-t', 'mangle', '-D', 'PREROUTING', '-p', 'tcp', '--dport', str(port), '--tcp-flags', 'RST', 'RST', '-j', 'DROP'],
        ['iptables', '-t', 'raw', '-A', 'PREROUTING', '-p', 'tcp', '--dport', str(port), '-j', 'NOTRACK'],
        ['iptables', '-t', 'raw', '-A', 'OUTPUT', '-p', 'tcp', '--sport', str(port), '-j', 'NOTRACK'],
        ['iptables', '-t', 'mangle', '-A', 'OUTPUT', '-p', 'tcp', '--sport', str(port), '--tcp-flags', 'RST', 'RST', '-j', 'DROP'],
        ['iptables', '-t', 'mangle', '-A', 'PREROUTING', '-p', 'tcp', '--dport', str(port), '--tcp-flags', 'RST', 'RST', '-j', 'DROP'],
    ]
    if not shutil.which('iptables'):
        return False
    for c in cmds:
        run(c, 4)
    save_iptables()
    return True


def client_firewall(server_ip, server_port):
    if not shutil.which('iptables'):
        return False
    cmds = [
        ['iptables', '-t', 'raw', '-D', 'OUTPUT', '-p', 'tcp', '-d', server_ip, '--dport', str(server_port), '-j', 'NOTRACK'],
        ['iptables', '-t', 'raw', '-D', 'PREROUTING', '-p', 'tcp', '-s', server_ip, '--sport', str(server_port), '-j', 'NOTRACK'],
        ['iptables', '-t', 'mangle', '-D', 'OUTPUT', '-p', 'tcp', '-d', server_ip, '--dport', str(server_port), '--tcp-flags', 'RST', 'RST', '-j', 'DROP'],
        ['iptables', '-t', 'mangle', '-D', 'PREROUTING', '-p', 'tcp', '-s', server_ip, '--sport', str(server_port), '--tcp-flags', 'RST', 'RST', '-j', 'DROP'],
        ['iptables', '-t', 'raw', '-A', 'OUTPUT', '-p', 'tcp', '-d', server_ip, '--dport', str(server_port), '-j', 'NOTRACK'],
        ['iptables', '-t', 'raw', '-A', 'PREROUTING', '-p', 'tcp', '-s', server_ip, '--sport', str(server_port), '-j', 'NOTRACK'],
        ['iptables', '-t', 'mangle', '-A', 'OUTPUT', '-p', 'tcp', '-d', server_ip, '--dport', str(server_port), '--tcp-flags', 'RST', 'RST', '-j', 'DROP'],
        ['iptables', '-t', 'mangle', '-A', 'PREROUTING', '-p', 'tcp', '-s', server_ip, '--sport', str(server_port), '--tcp-flags', 'RST', 'RST', '-j', 'DROP'],
    ]
    for c in cmds:
        run(c, 4)
    save_iptables()
    return True


def ensure_binary():
    return os.path.isfile(os.path.join(PAQET_DIR, 'paqet')) and os.access(os.path.join(PAQET_DIR, 'paqet'), os.X_OK)


def create_service(name, config):
    if not re.fullmatch(r'paqet(?:-[A-Za-z0-9_.-]+)?', name):
        raise ValueError('Invalid service name')
    unit = f'''[Unit]\nDescription=paqet Raw Packet Tunnel\nAfter=network.target\nStartLimitIntervalSec=0\n\n[Service]\nType=simple\nExecStart=/opt/paqet/paqet run -c {config}\nRestart=always\nRestartSec=5\nLimitNOFILE=65535\n\n[Install]\nWantedBy=multi-user.target\n'''
    path = f'/etc/systemd/system/{name}.service'
    with open(path, 'w', encoding='utf-8') as f:
        f.write(unit)
    run(['systemctl', 'daemon-reload'], 10)
    run(['systemctl', 'enable', name], 10)
    rc, out = run(['systemctl', 'restart', name], 15)
    time.sleep(1)
    active = run(['systemctl', 'is-active', '--quiet', name], 4)[0] == 0
    return active, out


def encode_connection(ip, port, key, fwd):
    payload = f'ip={ip};port={port};key={key};fwd={fwd}'
    raw = base64.urlsafe_b64encode(payload.encode()).decode().rstrip('=')
    return 'paqet://' + raw


def decode_connection(value):
    value = re.sub(r'\s+', '', str(value or ''))
    if not value.startswith('paqet://'):
        raise ValueError('Connection string must start with paqet://')
    b64 = value[len('paqet://'):]
    if not re.fullmatch(r'[A-Za-z0-9_-]+', b64):
        raise ValueError('Malformed connection string')
    b64 += '=' * ((4 - len(b64) % 4) % 4)
    try:
        payload = base64.urlsafe_b64decode(b64.encode()).decode()
    except Exception:
        raise ValueError('Could not decode connection string')
    values = {}
    for part in payload.split(';'):
        if '=' in part:
            k, v = part.split('=', 1)
            values[k] = v
    if not valid_ip(values.get('ip', '')) or not valid_port(values.get('port', '')) or not values.get('key'):
        raise ValueError('Connection string is missing required fields')
    fwd = values.get('fwd', '9090')
    if not valid_ports(fwd):
        raise ValueError('Invalid forward port in connection string')
    return {'ip': values['ip'], 'port': int(values['port']), 'key': values['key'], 'fwd': fwd}


def meta():
    return read_json(META_FILE, [])


def add_meta(item):
    rows = meta()
    rows = [x for x in rows if x.get('service') != item.get('service')]
    rows.append(item)
    write_json(META_FILE, rows)


def service_rows():
    rc, out = run(['systemctl', 'list-units', '--type=service', '--all', '--no-legend', '--plain'], 6)
    rows = []
    if rc == 0:
        for line in out.splitlines():
            m = re.match(r'\s*(paqet(?:-[^\s]+)?)\.service\s+(\w+)\s+(\w+)\s+(\w+)\s+(.*)', line)
            if m:
                rows.append({'name': m.group(1), 'active': m.group(2), 'status': m.group(5).strip()})
    return rows


def config_text(path=None):
    path = path or os.path.join(PAQET_DIR, 'config.yaml')
    try:
        with open(path, encoding='utf-8') as f:
            return f.read()
    except Exception:
        return ''


def infer_endpoints():
    rows = []
    for cfg in [os.path.join(PAQET_DIR, 'config.yaml')] + sorted(
        os.path.join(PAQET_DIR, x) for x in os.listdir(PAQET_DIR) if x.startswith('config-') and x.endswith('.yaml')
    ) if os.path.isdir(PAQET_DIR) else []:
        text = config_text(cfg)
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        port = ''
        m = re.search(r'addr:\s*"[^:]+:(\d+)"', text)
        if m:
            port = m.group(1)
        rows.append({'config': cfg, 'ips': list(dict.fromkeys(ips))[:8], 'port': port})
    return rows


def metrics():
    rc, load = run(['cat', '/proc/loadavg'], 2)
    load1 = float(load.split()[0]) if rc == 0 and load else 0
    cpu_count = os.cpu_count() or 1
    rc, mem = run(['cat', '/proc/meminfo'], 2)
    total = avail = 0
    if rc == 0:
        for l in mem.splitlines():
            if l.startswith('MemTotal:'): total = int(l.split()[1]) * 1024
            elif l.startswith('MemAvailable:'): avail = int(l.split()[1]) * 1024
    used = max(total - avail, 0)
    rc, df = run(['df', '-B1', PAQET_DIR], 3)
    disk = {}
    if rc == 0 and len(df.splitlines()) > 1:
        x = df.splitlines()[-1].split()
        if len(x) >= 5:
            disk = {'total': int(x[1]), 'used': int(x[2]), 'percent': x[4]}
    try:
        uptime = float(open('/proc/uptime').read().split()[0])
    except Exception:
        uptime = 0
    return {
        'load': load1,
        'cpu_percent': round(min(load1 / cpu_count * 100, 100), 1),
        'memory': {'total': total, 'used': used, 'percent': round(used / total * 100, 1) if total else 0},
        'disk': disk,
        'uptime': uptime,
    }


class H(BaseHTTPRequestHandler):
    server_version = 'PAQETPanel/2.1'

    def log_message(self, fmt, *args):
        pass

    def send_bytes(self, raw, content_type='application/octet-stream', code=200):
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def send_json(self, obj, code=200):
        self.send_bytes(json.dumps(obj, ensure_ascii=False).encode(), 'application/json; charset=utf-8', code)

    def body(self):
        n = int(self.headers.get('Content-Length', '0'))
        return json.loads(self.rfile.read(n) or b'{}')

    def auth(self):
        return self.headers.get('X-Session', '') in SESSIONS

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ('/', '/index.html'):
            try:
                with open(os.path.join(STATIC_DIR, 'index.html'), 'rb') as f:
                    return self.send_bytes(f.read(), 'text/html; charset=utf-8')
            except Exception:
                return self.send_json({'error': 'Panel assets missing'}, 500)
        if path.startswith('/static/'):
            rel = unquote(path[len('/static/'):]).lstrip('/')
            full = os.path.normpath(os.path.join(STATIC_DIR, rel))
            if not full.startswith(os.path.abspath(STATIC_DIR) + os.sep) or not os.path.isfile(full):
                return self.send_json({'error': 'Not found'}, 404)
            ctype = 'image/png' if full.endswith('.png') else 'image/svg+xml' if full.endswith('.svg') else 'text/plain; charset=utf-8'
            with open(full, 'rb') as f:
                return self.send_bytes(f.read(), ctype)
        if path == '/api/bootstrap':
            return self.send_json({'ok': True, 'authenticated': self.auth(), 'port': PORT, 'project': 'paqet-tunnel', 'author': 'durwinam'})
        if not self.auth():
            return self.send_json({'error': 'unauthorized'}, 401)
        if path == '/api/network':
            return self.send_json(network_info())
        if path == '/api/dashboard':
            rows = service_rows()
            return self.send_json({'metrics': metrics(), 'services': rows, 'endpoints': infer_endpoints(), 'tunnels': meta(), 'config_exists': bool(infer_endpoints())})
        if path == '/api/logs':
            q = parse_qs(urlparse(self.path).query).get('service', ['paqet'])[0]
            if not re.fullmatch(r'paqet(?:-[A-Za-z0-9_.-]+)?', q): q = 'paqet'
            rc, out = run(['journalctl', '-u', q, '-n', '160', '--no-pager', '-o', 'short-iso'], 8)
            return self.send_json({'service': q, 'logs': out})
        if path == '/api/config':
            return self.send_json({'config': config_text()})
        if path == '/api/connection':
            rows = [x for x in meta() if x.get('role') == 'server']
            if not rows:
                return self.send_json({'ok': False, 'error': 'No abroad server configuration found.'}, 404)
            x = rows[-1]
            return self.send_json({'ok': True, 'connection': x.get('connection', ''), 'details': x})
        return self.send_json({'error': 'not found'}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            data = self.body()
        except Exception:
            data = {}
        if path == '/api/login':
            u = str(data.get('username', ''))
            p = str(data.get('password', ''))
            if u == AUTH['username'] and hashlib.sha256(p.encode()).hexdigest() == AUTH['password_sha256']:
                token = secrets.token_urlsafe(32)
                SESSIONS.add(token)
                return self.send_json({'ok': True, 'session': token})
            return self.send_json({'ok': False, 'error': 'Invalid credentials'}, 401)
        if not self.auth():
            return self.send_json({'error': 'unauthorized'}, 401)

        if path == '/api/tunnel/create-abroad':
            try:
                if not ensure_binary():
                    raise ValueError('paqet binary is not installed. Run the main paqet-tunnel installer first.')
                net = data.get('network') or network_info()
                iface = str(net.get('interface', '')).strip()
                local_ip = str(net.get('local_ip', '')).strip()
                public_ip = str(net.get('public_ip', '')).strip()
                gateway_mac = str(net.get('gateway_mac', '')).strip()
                if not iface or not valid_ip(local_ip) or not valid_ip(public_ip) or not re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', gateway_mac):
                    raise ValueError('Network settings are incomplete or invalid.')
                tunnel_port = int(data.get('tunnel_port') or 8888)
                fwd = str(data.get('forward_ports') or '9090').replace(' ', '')
                if not valid_port(tunnel_port) or not valid_ports(fwd):
                    raise ValueError('Invalid tunnel or forward port.')
                if str(tunnel_port) in [x.strip() for x in fwd.split(',')]:
                    raise ValueError('Tunnel port cannot be the same as a forwarded port.')
                key = str(data.get('secret_key') or secrets.token_urlsafe(24))
                if len(key) < 8:
                    raise ValueError('Secret key is too short.')
                cfg = os.path.join(PAQET_DIR, 'config.yaml')
                text = f'''# paqet Server Configuration\n# Created from PAQET Web Panel\n# inbound_ports: {fwd}\nrole: "server"\n\nlog:\n  level: "info"\n\nlisten:\n  addr: ":{tunnel_port}"\n\nnetwork:\n  interface: "{iface}"\n  ipv4:\n    addr: "{local_ip}:{tunnel_port}"\n    router_mac: "{gateway_mac}"\n  tcp:\n    local_flag: ["PA"]\n    remote_flag: ["PA"]\n  pcap:\n    sockbuf: 8388608\n\ntransport:\n  protocol: "kcp"\n  conn: 1\n  kcp:\n    mode: "fast"\n    key: "{key}"\n    mtu: 1280\n'''
                os.makedirs(PAQET_DIR, exist_ok=True)
                with open(cfg, 'w', encoding='utf-8') as f:
                    f.write(text)
                server_firewall(tunnel_port)
                active, service_out = create_service('paqet', cfg)
                connection = encode_connection(public_ip, tunnel_port, key, fwd)
                add_meta({'role': 'server', 'service': 'paqet', 'label': 'خارج', 'ip': public_ip, 'tunnel_port': tunnel_port, 'forward_ports': fwd, 'connection': connection, 'created_at': int(time.time()), 'active': active})
                return self.send_json({'ok': True, 'active': active, 'connection': connection, 'details': {'ip': public_ip, 'tunnel_port': tunnel_port, 'forward_ports': fwd}, 'service_output': service_out})
            except Exception as e:
                return self.send_json({'ok': False, 'error': str(e)}, 400)

        if path == '/api/tunnel/decode':
            try:
                return self.send_json({'ok': True, 'details': decode_connection(data.get('connection', ''))})
            except Exception as e:
                return self.send_json({'ok': False, 'error': str(e)}, 400)

        if path == '/api/tunnel/create-iran':
            try:
                if not ensure_binary():
                    raise ValueError('paqet binary is not installed. Run the main paqet-tunnel installer first.')
                details = decode_connection(data.get('connection', ''))
                name = re.sub(r'[^A-Za-z0-9_.-]+', '-', str(data.get('name') or 'iran')).strip('-')[:40] or 'iran'
                net = data.get('network') or network_info()
                iface = str(net.get('interface', '')).strip()
                local_ip = str(net.get('local_ip', '')).strip()
                gateway_mac = str(net.get('gateway_mac', '')).strip()
                if not iface or not valid_ip(local_ip) or not re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', gateway_mac):
                    raise ValueError('Iran server network settings are incomplete or invalid.')
                fwd = str(data.get('forward_ports') or details['fwd']).replace(' ', '')
                if not valid_ports(fwd):
                    raise ValueError('Invalid forward port.')
                if str(details['port']) in [x.strip() for x in fwd.split(',')]:
                    raise ValueError('Tunnel port cannot be the same as a forwarded port.')
                cfg = os.path.join(PAQET_DIR, f'config-{name}.yaml')
                service = f'paqet-{name}'
                forward_config = ''.join(f'\n  - listen: "0.0.0.0:{p}"\n    target: "127.0.0.1:{p}"\n    protocol: "tcp"' for p in [x.strip() for x in fwd.split(',')])
                text = f'''# paqet Client Configuration (Port Forwarding Mode)\n# Tunnel: {name}\n# Created from PAQET Web Panel\nrole: "client"\n\nlog:\n  level: "info"\n\nforward:{forward_config}\n\nnetwork:\n  interface: "{iface}"\n  ipv4:\n    addr: "{local_ip}:0"\n    router_mac: "{gateway_mac}"\n  tcp:\n    local_flag: ["PA"]\n    remote_flag: ["PA"]\n  pcap:\n    sockbuf: 4194304\n\nserver:\n  addr: "{details['ip']}:{details['port']}"\n\ntransport:\n  protocol: "kcp"\n  conn: 1\n  kcp:\n    mode: "fast"\n    key: "{details['key']}"\n    mtu: 1280\n'''
                with open(cfg, 'w', encoding='utf-8') as f:
                    f.write(text)
                client_firewall(details['ip'], details['port'])
                active, service_out = create_service(service, cfg)
                add_meta({'role': 'client', 'service': service, 'label': 'ایران', 'ip': local_ip, 'server_ip': details['ip'], 'tunnel_port': details['port'], 'forward_ports': fwd, 'created_at': int(time.time()), 'active': active})
                return self.send_json({'ok': True, 'active': active, 'service': service, 'details': {'server_ip': details['ip'], 'tunnel_port': details['port'], 'forward_ports': fwd}, 'service_output': service_out})
            except Exception as e:
                return self.send_json({'ok': False, 'error': str(e)}, 400)

        if path == '/api/service':
            name = str(data.get('name', ''))
            action = str(data.get('action', ''))
            if not re.fullmatch(r'paqet(?:-[A-Za-z0-9_.-]+)?', name) or action not in ('start', 'stop', 'restart'):
                return self.send_json({'error': 'invalid request'}, 400)
            rc, out = run(['systemctl', action, name], 15)
            return self.send_json({'ok': rc == 0, 'output': out}, 200 if rc == 0 else 500)

        if path == '/api/ping':
            target = str(data.get('target', ''))
            if not (valid_ip(target) or re.fullmatch(r'[A-Za-z0-9_.:-]+', target)):
                return self.send_json({'error': 'invalid target'}, 400)
            rc, out = run(['ping', '-c', '5', '-W', '2', target], 15)
            avg = loss = None
            m = re.search(r'=\s*[\d.]+/([\d.]+)/', out)
            if m: avg = float(m.group(1))
            m = re.search(r'(\d+(?:\.\d+)?)%\s*packet loss', out)
            if m: loss = float(m.group(1))
            return self.send_json({'ok': rc == 0, 'target': target, 'latency_ms': avg, 'packet_loss': loss, 'raw': out})

        if path == '/api/speedtest':
            for c in (['speedtest', '--simple'], ['speedtest-cli', '--simple']):
                rc, out = run(c, 60)
                if rc == 0:
                    return self.send_json({'ok': True, 'raw': out})
            return self.send_json({'ok': False, 'message': 'Install speedtest or speedtest-cli on the server to enable Speed Test.'})

        if path == '/api/password':
            old, new = str(data.get('old', '')), str(data.get('new', ''))
            if hashlib.sha256(old.encode()).hexdigest() != AUTH['password_sha256'] or len(new) < 8:
                return self.send_json({'error': 'Invalid current password or new password too short'}, 400)
            AUTH['password_sha256'] = hashlib.sha256(new.encode()).hexdigest()
            AUTH.pop('generated_password', None)
            write_json(STATE_FILE, AUTH)
            return self.send_json({'ok': True})

        if path == '/api/logout':
            SESSIONS.discard(self.headers.get('X-Session', ''))
            return self.send_json({'ok': True})
        return self.send_json({'error': 'not found'}, 404)


if __name__ == '__main__':
    print(f'PAQET Panel listening on :{PORT}')
    ThreadingHTTPServer((HOST, PORT), H).serve_forever()
