#!/usr/bin/env python3
"""Pinned Linux/systemd deployment, also renders configs for portable testing."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
ROLE = (ROOT / 'ROLE').read_text().strip()
FRP = 'frps' if ROLE == 'relay' else 'frpc'

def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(value if isinstance(value, str) else json.dumps(value, indent=2) + '\n')
    path.chmod(0o600)

def port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError('port must be an integer in 1..65535')
    return value

def identity(value):
    uuid.UUID(value)
    return value

def services(cfg):
    values = cfg['services']
    if not 1 <= len(values) <= 32:
        raise ValueError('configure 1..32 explicitly authorized services')
    names, ports = set(), set()
    for item in values:
        name, number = item['id'], port(item['remotePort'])
        if not name or not all(c.isalnum() or c in '-_' for c in name) or name in names or number in ports:
            raise ValueError('service ids and mapping ports must be unique')
        names.add(name); ports.add(number)
    return values

def outbound(cfg, user):
    proxy = cfg['proxy']
    identity(proxy[user + 'UUID'])
    tls = {'enabled': True, 'server_name': proxy['serverName']}
    if not tls['server_name'] or not proxy['host']:
        raise ValueError('proxy host and TLS serverName are required')
    if proxy.get('caCertificate'):
        tls['certificate'] = proxy['caCertificate']
    return {'type': 'vless', 'tag': 'relay', 'server': proxy['host'],
            'server_port': port(proxy['port']), 'uuid': proxy[user + 'UUID'], 'tls': tls}

def render(cfg, directory):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    items = services(cfg)
    control = port(cfg.get('controlPort', 7000))
    if control in [s['remotePort'] for s in items]:
        raise ValueError('control port collides with a media mapping')
    if len(cfg['frpToken']) < 32:
        raise ValueError('frpToken must have at least 32 characters')
    # JSON strings are TOML-compatible for these scalar values.
    q = json.dumps
    if ROLE == 'relay':
        proxy = cfg['proxy']
        for user in ['app', 'home']:
            identity(proxy[user + 'UUID'])
        if proxy['appUUID'] == proxy['homeUUID']:
            raise ValueError('home and app identities must be distinct')
        if port(proxy['port']) in [control] + [s['remotePort'] for s in items]:
            raise ValueError('proxy port collides with frp ports')
        # Each deployment is one household. Independent households use separate
        # instances; a shared frp token is not a multi-tenant authorization system.
        rules = [{'auth_user': ['home'], 'ip_cidr': ['127.0.0.1/32'], 'port': [control], 'action': 'route', 'outbound': 'direct'},
                 {'auth_user': ['app'], 'ip_cidr': ['127.0.0.1/32'], 'port': [s['remotePort'] for s in items], 'action': 'route', 'outbound': 'direct'},
                 {'action': 'reject'}]
        sing = {'log': {'level': 'warn', 'timestamp': True},
                'inbounds': [{'type': 'vless', 'tag': 'proxy', 'listen': cfg.get('listen', '0.0.0.0'), 'listen_port': port(proxy['port']),
                              'users': [{'name': u, 'uuid': proxy[u+'UUID']} for u in ['app','home']],
                              'tls': {'enabled': True, 'certificate_path': str(Path(proxy['certificatePath']).resolve()), 'key_path': str(Path(proxy['keyPath']).resolve())}}],
                'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'rules': rules}}
        frp = '\n'.join(['bindAddr = "127.0.0.1"', f'bindPort = {control}', 'proxyBindAddr = "127.0.0.1"',
            'auth.method = "token"', f'auth.token = {q(cfg["frpToken"])}', 'auth.additionalScopes = ["HeartBeats", "NewWorkConns"]',
            'transport.tls.force = true', f'transport.tls.certFile = {q(str(Path(cfg["frpCertificatePath"]).resolve()))}',
            f'transport.tls.keyFile = {q(str(Path(cfg["frpKeyPath"]).resolve()))}',
            'allowPorts = [' + ', '.join('{ single = '+str(s['remotePort'])+' }' for s in items) + ']',
            'log.to = "console"', 'log.level = "warn"', ''])
    else:
        socks = port(cfg.get('socksPort',1080))
        sing = {'log': {'level': 'warn', 'timestamp': True},
                'inbounds': [{'type': 'socks', 'listen': '127.0.0.1', 'listen_port': socks}],
                'outbounds': [outbound(cfg, 'home')], 'route': {'final': 'relay'}}
        frp = '\n'.join(['serverAddr = "127.0.0.1"', f'serverPort = {control}', 'loginFailExit = false',
            'auth.method = "token"', f'auth.token = {q(cfg["frpToken"])}', 'auth.additionalScopes = ["HeartBeats", "NewWorkConns"]',
            'transport.protocol = "tcp"', f'transport.proxyURL = "socks5://127.0.0.1:{socks}"',
            'transport.tls.enable = true', f'transport.tls.serverName = {q(cfg["frpServerName"])}',
            f'transport.tls.trustedCaFile = {q(str(Path(cfg["frpCAPath"]).resolve()))}',
            'log.to = "console"', 'log.level = "warn"', ''])
        for s in items:
            host = s['localHost']
            if not host or any(c in host for c in '/\\\n'):
                raise ValueError('invalid localHost')
            frp += '\n'.join(['\n[[proxies]]', f'name = {q(s["id"])}', 'type = "tcp"',
                f'localIP = {q(host)}', f'localPort = {port(s["localPort"])}', f'remotePort = {port(s["remotePort"])}',
                'healthCheck.type = "tcp"', 'healthCheck.intervalSeconds = 10', ''])
    write(directory/'sing-box.json', sing)
    write(directory/(FRP+'.toml'), frp)

def check(directory, binaries):
    # Never echo command output: validators may include configuration secrets.
    for args in [[str(binaries/'sing-box'), 'check', '-c', str(directory/'sing-box.json')],
                 [str(binaries/FRP), 'verify', '-c', str(directory/(FRP+'.toml'))]]:
        completed = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if completed.returncode:
            raise ValueError('upstream config validation failed for ' + Path(args[0]).name)

def download(binaries):
    system = platform.system().lower()
    arch = {'x86_64':'amd64','aarch64':'arm64','arm64':'arm64'}.get(platform.machine())
    lock = json.loads((ROOT/'versions.lock.json').read_text())
    for component in ['sing-box', FRP]:
        entry = lock[component][f'{system}-{arch}']
        with urllib.request.urlopen(entry['url'], timeout=60) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != entry['sha256']:
            raise ValueError('download checksum mismatch')
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp)/'archive.tar.gz'; archive.write_bytes(data)
            with tarfile.open(archive) as tar:
                matches = [m for m in tar.getmembers() if m.isfile() and Path(m.name).name == component]
                if len(matches) != 1:
                    raise ValueError('unexpected upstream archive')
                content = tar.extractfile(matches[0]).read()
            binaries.mkdir(parents=True, exist_ok=True)
            dest = binaries/component; dest.write_bytes(content); dest.chmod(0o755)

def wait_socks(number):
    for _ in range(30):
        try:
            with socket.create_connection(('127.0.0.1', number), timeout=1) as sock:
                sock.sendall(b'\x05\x01\x00')
                if sock.recv(2) == b'\x05\x00': return
        except OSError: pass
        time.sleep(1)
    raise ValueError('sing-box SOCKS entry is unavailable; refusing direct frpc fallback')

def unit(prefix, name, cfg):
    binary = prefix/'current/bin'/name
    filename = 'sing-box.json' if name == 'sing-box' else FRP+'.toml'
    args = 'run -c' if name == 'sing-box' else '-c'
    dependencies = ''
    pre = ''
    if ROLE == 'home' and name == 'frpc':
        dependencies = f'Requires=openplayx-{ROLE}-sing-box.service\nAfter=openplayx-{ROLE}-sing-box.service\n'
        pre = f'ExecStartPre=/usr/bin/python3 {prefix}/manager.py wait-socks --output {prefix}/current/config\n'
    return f'''[Unit]
Description=OpenPlayX {ROLE} {name}
After=network-online.target
Wants=network-online.target
{dependencies}
[Service]
Type=simple
DynamicUser=yes
{pre}ExecStart={binary} {args} {prefix}/current/config/{filename}
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadOnlyPaths={prefix}
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
# Config directories must be readable by the service via a dedicated group.
SupplementaryGroups=openplayx-{ROLE}
UMask=0077

[Install]
WantedBy=multi-user.target
'''

def systemctl(action):
    subprocess.run(['systemctl', action] + [f'openplayx-{ROLE}-{n}.service' for n in ['sing-box',FRP]], check=True)

def restrict_release(prefix, release, gid):
    for path in [prefix, prefix/'releases', release, *list(release.rglob('*'))]:
        os.chown(path,0,gid)
        path.chmod(0o750 if path.is_dir() or path.parent == release/'bin' else 0o640)

def install(cfg, prefix):
    if platform.system() != 'Linux' or os.geteuid() != 0:
        raise ValueError('install requires Linux, systemd and root; render/check work without root')
    if ' ' in str(prefix): raise ValueError('prefix cannot contain spaces')
    subprocess.run(['groupadd','--system',f'openplayx-{ROLE}'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    prefix.mkdir(parents=True, exist_ok=True)
    release = prefix/'releases'/str(time.time_ns())
    release.mkdir(parents=True)
    previous = (prefix/'current').resolve() if (prefix/'current').exists() else None
    try:
        download(release/'bin')
        cfg = json.loads(json.dumps(cfg))
        tlsdir=release/'config/tls'; tlsdir.mkdir(parents=True)
        fields=[(cfg['proxy'],'certificatePath'),(cfg['proxy'],'keyPath'),(cfg,'frpCertificatePath'),(cfg,'frpKeyPath')] if ROLE=='relay' else [(cfg,'frpCAPath')]
        for index,(owner,key) in enumerate(fields):
            source=Path(owner[key]); dest=tlsdir/(str(index)+'-'+source.name)
            shutil.copyfile(source,dest); owner[key]=str(dest)
        render(cfg, release/'config'); check(release/'config',release/'bin')
        # Configs hold secrets: only root and the service group may read them.
        import grp
        gid = grp.getgrnam(f'openplayx-{ROLE}').gr_gid
        restrict_release(prefix,release,gid)
        # Certificate/key paths also need group access; never change user files.
        shutil.copy2(__file__, prefix/'manager.py')
        (prefix/'ROLE').write_text(ROLE)
        # Installed manager reads its ROLE next to itself.
        script = (prefix/'manager.py').read_text().replace('Path(__file__).resolve().parents[1]', 'Path(__file__).resolve().parent')
        (prefix/'manager.py').write_text(script)
        (prefix/'manager.py').chmod(0o644)
        (prefix/'ROLE').chmod(0o644)
        for name in ['sing-box',FRP]:
            Path('/etc/systemd/system',f'openplayx-{ROLE}-{name}.service').write_text(unit(prefix,name,cfg))
        link = prefix/'next'; link.unlink(missing_ok=True); link.symlink_to(release); link.replace(prefix/'current')
        subprocess.run(['systemctl','daemon-reload'],check=True)
        systemctl('enable'); systemctl('restart')
        time.sleep(2); systemctl('is-active')
        if previous:
            old = prefix/'previous'
            old.unlink(missing_ok=True); old.symlink_to(previous)
    except BaseException:
        if previous:
            link = prefix/'restore'; link.symlink_to(previous); link.replace(prefix/'current')
            systemctl('restart')
        else:
            systemctl('stop')
            (prefix/'current').unlink(missing_ok=True)
        raise

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['render','check','install','update','start','stop','status','rollback','uninstall','wait-socks'])
    parser.add_argument('--config',type=Path,default=Path('deployment.json'))
    parser.add_argument('--output',type=Path,default=Path('generated'))
    parser.add_argument('--bin',type=Path,default=Path('bin'))
    parser.add_argument('--prefix',type=Path,default=Path('/opt/openplayx-'+ROLE))
    parser.add_argument('--port',type=int,default=1080)
    args = parser.parse_args()
    if args.action == 'render': render(json.loads(args.config.read_text()),args.output)
    elif args.action == 'check': check(args.output.resolve(),args.bin.resolve())
    elif args.action in ['install','update']: install(json.loads(args.config.read_text()), args.prefix.resolve())
    elif args.action == 'wait-socks':
        config=args.output/'sing-box.json'
        number=json.loads(config.read_text())['inbounds'][0]['listen_port'] if config.exists() else args.port
        wait_socks(port(number))
    elif args.action in ['start','stop','status']: systemctl({'start':'restart','status':'status'}.get(args.action,args.action))
    elif args.action == 'rollback':
        previous=args.prefix/'previous'
        if not previous.exists(): raise ValueError('no previous release')
        link=args.prefix/'restore'; link.symlink_to(previous.resolve()); link.replace(args.prefix/'current'); systemctl('restart')
    elif args.action == 'uninstall':
        systemctl('disable'); systemctl('stop')
        for name in ['sing-box',FRP]: Path('/etc/systemd/system',f'openplayx-{ROLE}-{name}.service').unlink(missing_ok=True)
        subprocess.run(['systemctl','daemon-reload'],check=True)
        print('Services removed. Configuration, credentials and releases preserved at',args.prefix)
if __name__ == '__main__':
    os.umask(0o077)
    try: main()
    except (ValueError,KeyError,OSError,subprocess.CalledProcessError):
        print('Operation failed. Check config fields, permissions, certificates and service status. Secrets were not logged.',file=sys.stderr)
        sys.exit(1)
