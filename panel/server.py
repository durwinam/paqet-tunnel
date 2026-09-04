#!/usr/bin/env python3
import json, os, re, socket, subprocess, time, secrets, hashlib
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HOST = os.environ.get('PAQET_PANEL_HOST', '0.0.0.0')
PORT = int(os.environ.get('PAQET_PANEL_PORT', '6102'))
ROOT = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(ROOT, 'static')
PAQET_DIR = os.environ.get('PAQET_DIR', '/opt/paqet')
CREDENTIALS = os.path.join(ROOT, 'credentials.json')
SESSIONS = set()


def run(cmd, timeout=8):
    try:
        p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout, check=False)
        return p.returncode, p.stdout.strip()
    except Exception as e:
        return 1, str(e)


def service_active(name):
    rc, _ = run(['systemctl', 'is-active', '--quiet', name], 3)
    return rc == 0


def get_role(path):
    try:
        with open(path, encoding='utf-8', errors='ignore') as f:
            for line in f:
                if line.strip().startswith('role:'):
                    return line.split(':', 1)[1].strip().strip('"\'')
    except OSError:
        pass
    return 'unknown'


def get_value(path, key):
    pat = re.compile(r'^\s*' + re.escape(key) + r'\s*:\s*["\']?([^"\'\s#]+)')
    try:
        with open(path, encoding='utf-8', errors='ignore') as f:
            for line in f:
                m = pat.match(line)
                if m:
                    return m.group(1)
    except OSError:
        pass
    return None


def configs():
    try:
        files = [os.path.join(PAQET_DIR, x) for x in os.listdir(PAQET_DIR)
                 if re.match(r'^config(?:-[^/]+)?\.yaml$', x)]
    except OSError:
        return []
    return sorted(files)


def tunnel_name(path):
    base = os.path.basename(path)
    return 'default' if base == 'config.yaml' else re.sub(r'^config-|\.yaml$', '', base)


def service_for(path):
    name = tunnel_name(path)
    return 'paqet' if name == 'default' else 'paqet-' + name


def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('1.1.1.1', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


def public_ip():
    rc, out = run(['curl', '-4', '-fsS', '--max-time', '3', 'https://api.ipify.org'], 5)
    return out if rc == 0 and re.match(r'^\d+\.\d+\.\d+\.\d+$', out) else None


def meminfo():
    data = {}
    try:
        with open('/proc/meminfo') as f:
            for line in f:
                k, v = line.split(':', 1)
                data[k] = int(v.strip().split()[0])
        total = data.get('MemTotal', 0)
        avail = data.get('MemAvailable', data.get('MemFree', 0))
        used = max(total - avail, 0)
        return {'total_mb': round(total/1024), 'used_mb': round(used/1024),
                'percent': round(used*100/total, 1) if total else 0}
    except Exception:
        return {'total_mb': 0, 'used_mb': 0, 'percent': 0}


def cpu_percent():
    try:
        def read():
            vals = open('/proc/stat').readline().split()[1:]
            nums = list(map(int, vals))
            idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
            return sum(nums), idle
        a = read(); time.sleep(.08); b = read()
        total = b[0]-a[0]; idle = b[1]-a[1]
        return round((total-idle)*100/total, 1) if total else 0
    except Exception:
        return 0


def disk():
    rc, out = run(['df', '-P', '/'], 3)
    try:
        row = out.splitlines()[-1].split()
        return {'total': row[1], 'used': row[2], 'free': row[3], 'percent': int(row[4].rstrip('%'))}
    except Exception:
        return {'total': '-', 'used': '-', 'free': '-', 'percent': 0}


def uptime():
    try:
        seconds = float(open('/proc/uptime').read().split()[0])
        d, rem = divmod(int(seconds), 86400)
        h, rem = divmod(rem, 3600)
        m = rem // 60
        return f'{d}d {h}h {m}m' if d else f'{h}h {m}m'
    except Exception:
        return '-'


def traffic():
    rx = tx = 0
    try:
        with open('/proc/net/dev') as f:
            for line in f:
                if ':' not in line: continue
                vals = line.split(':', 1)[1].split()
                if len(vals) >= 9:
                    rx += int(vals[0]); tx += int(vals[8])
    except Exception:
        pass
    return {'rx_bytes': rx, 'tx_bytes': tx}


def state():
    cs = configs()
    items = []
    for path in cs:
        role = get_role(path)
        name = tunnel_name(path)
        svc = service_for(path)
        active = service_active(svc)
        remote = None
        if role == 'client':
            try:
                text = open(path, encoding='utf-8', errors='ignore').read()
                m = re.search(r'^\s*addr:\s*["\']?([^"\'\s]+)', text, re.M)
                remote = m.group(1) if m else None
            except OSError:
                pass
        items.append({'name': name, 'role': role, 'service': svc, 'active': active,
                      'remote': remote, 'config': path})
    roles = {x['role'] for x in items}
    if 'server' in roles and 'client' in roles: role = 'mixed'
    elif 'server' in roles: role = 'server'
    elif 'client' in roles: role = 'client'
    else: role = 'none'
    t = traffic()
    return {'role': role, 'hostname': socket.gethostname(), 'local_ip': local_ip(),
            'public_ip': public_ip(), 'cpu': cpu_percent(), 'memory': meminfo(),
            'disk': disk(), 'uptime': uptime(), 'traffic': t, 'tunnels': items,
            'server_online': any(x['role']=='server' and x['active'] for x in items),
            'tunnel_online': any(x['role']=='client' and x['active'] for x in items)}


def get_credentials():
    try:
        with open(CREDENTIALS, encoding='utf-8') as f: return json.load(f)
    except Exception: return {'username':'admin','password_hash': hashlib.sha256(b'admin').hexdigest()}

def authorized(handler):
    raw = handler.headers.get('Cookie','')
    c = cookies.SimpleCookie(); c.load(raw)
    token = c.get('paqet_session')
    return bool(token and token.value in SESSIONS)

def ping(host, count=5):
    if not re.match(r'^[A-Za-z0-9_.:-]+$', host or ''):
        return {'ok': False, 'error': 'Invalid host'}
    rc, out = run(['ping', '-c', str(max(1, min(int(count), 10))), '-W', '2', host], 20)
    avg = None; loss = None
    m = re.search(r'(\d+(?:\.\d+)?)% packet loss', out)
    if m: loss = float(m.group(1))
    m = re.search(r'=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms', out)
    if m: avg = float(m.group(2))
    return {'ok': rc == 0, 'host': host, 'avg_ms': avg, 'packet_loss': loss, 'raw': out[-3000:]}


def speedtest():
    # Prefer an installed speedtest-cli binary when available.
    for binary in ('speedtest', 'speedtest-cli'):
        rc, out = run([binary, '--simple'], 60)
        if rc == 0:
            down = re.search(r'Download:\s*([\d.]+)\s*Mbit/s', out, re.I)
            up = re.search(r'Upload:\s*([\d.]+)\s*Mbit/s', out, re.I)
            lat = re.search(r'Ping:\s*([\d.]+)\s*ms', out, re.I)
            return {'ok': True, 'download_mbps': float(down.group(1)) if down else None,
                    'upload_mbps': float(up.group(1)) if up else None,
                    'latency_ms': float(lat.group(1)) if lat else None, 'raw': out}
    # Lightweight server-side download benchmark fallback. Upload is intentionally
    # reported as unavailable instead of fabricating a number.
    url = 'https://speed.cloudflare.com/__down?bytes=25000000'
    rc, out = run(['curl', '-4', '-L', '-o', '/dev/null', '-sS', '-w', '%{speed_download} %{time_total}',
                   '--max-time', '30', url], 35)
    try:
        bps, secs = map(float, out.split())
        return {'ok': rc == 0, 'download_mbps': round(bps*8/1e6, 2), 'upload_mbps': None,
                'latency_ms': None, 'raw': 'Cloudflare download benchmark'}
    except Exception:
        return {'ok': False, 'error': 'No speedtest binary and fallback benchmark failed', 'raw': out}


class Handler(BaseHTTPRequestHandler):
    server_version = 'PAQETPanel/1.0'
    def log_message(self, *_): pass
    def send_json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code); self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Cache-Control','no-store'); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        p = urlparse(self.path)
        if p.path == '/api/auth': return self.send_json({'authenticated': authorized(self)})
        if p.path.startswith('/api/') and not authorized(self): return self.send_json({'ok':False,'error':'Authentication required'},401)
        if p.path == '/api/status': return self.send_json(state())
        if p.path == '/api/ping':
            q = parse_qs(p.query); return self.send_json(ping(q.get('host',['1.1.1.1'])[0]))
        if p.path == '/api/speedtest': return self.send_json(speedtest())
        if p.path == '/api/logs':
            q=parse_qs(p.query); name=q.get('service',['paqet'])[0]
            if not re.match(r'^paqet(?:-[A-Za-z0-9_.-]+)?$', name): return self.send_json({'ok':False,'error':'Invalid service'},400)
            rc,out=run(['journalctl','-u',name,'-n','100','--no-pager','-o','short-iso'],8)
            return self.send_json({'ok':rc==0,'service':name,'logs':out})
        path = p.path.lstrip('/') or 'index.html'
        if '..' in path: return self.send_error(400)
        full = os.path.join(STATIC, path)
        if not os.path.isfile(full): full = os.path.join(STATIC, 'index.html')
        ctype = 'text/html; charset=utf-8' if full.endswith('.html') else 'text/css' if full.endswith('.css') else 'application/javascript' if full.endswith('.js') else 'image/jpeg' if full.endswith('.jpg') else 'application/octet-stream'
        data = open(full,'rb').read(); self.send_response(200); self.send_header('Content-Type',ctype); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_POST(self):
        p = urlparse(self.path)
        if p.path == '/api/login':
            try: data=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0')) or 0) or b'{}')
            except Exception: data={}
            cred=get_credentials(); expected=cred.get('password_hash','')
            ok=data.get('username')==cred.get('username','admin') and hashlib.sha256(str(data.get('password','')).encode()).hexdigest()==expected
            if not ok: return self.send_json({'ok':False,'error':'Invalid username or password'},401)
            token=secrets.token_urlsafe(32); SESSIONS.add(token)
            body=json.dumps({'ok':True}).encode(); self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Set-Cookie',f'paqet_session={token}; HttpOnly; SameSite=Strict; Path=/'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body); return
        if p.path.startswith('/api/') and not authorized(self): return self.send_json({'ok':False,'error':'Authentication required'},401)
        if p.path == '/api/service':
            n = re.match(r'^paqet(?:-[A-Za-z0-9_.-]+)?$', (parse_qs(p.query).get('name',[''])[0]))
            action = parse_qs(p.query).get('action',[''])[0]
            if not n or action not in ('start','stop','restart'): return self.send_json({'ok':False,'error':'Invalid request'},400)
            name = n.group(0)
            rc, out = run(['systemctl', action, name], 15)
            return self.send_json({'ok':rc==0,'service':name,'output':out}, 200 if rc==0 else 500)
        return self.send_json({'ok':False,'error':'Not found'},404)

if __name__ == '__main__':
    print(f'PAQET Panel listening on {HOST}:{PORT}')
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
