#!/usr/bin/env python3
"""Install the fixed local management service (Linux/systemd, root only)."""
import argparse
import os
from pathlib import Path
import platform
import shutil
import subprocess

from configuration import Configuration

ROOT=Path(__file__).resolve().parents[1]
ROLE=(ROOT/'ROLE').read_text().strip()
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config-dir',type=Path,default=Path('/var/lib/openplayx-'+ROLE))
    p.add_argument('--prefix',type=Path,default=Path('/opt/openplayx-'+ROLE))
    p.add_argument('--uninstall',action='store_true')
    p.add_argument('--enable-lan',action='store_true',help='Home only: migrate an existing loopback configuration to LAN access')
    args=p.parse_args()
    if args.enable_lan and (ROLE!='home' or args.uninstall):p.error('--enable-lan is only supported when installing Home')
    if platform.system()!='Linux' or os.geteuid()!=0:p.error('requires Linux, systemd and root')
    directory=args.config_dir.resolve();prefix=args.prefix.resolve()
    if any(c.isspace() for c in str(directory)+str(prefix)):p.error('paths cannot contain whitespace')
    unit='openplayx-'+ROLE+'-manager.service';unitpath=Path('/etc/systemd/system')/unit
    if args.uninstall:
        subprocess.run(['systemctl','disable','--now',unit],check=True)
        unitpath.unlink(missing_ok=True);subprocess.run(['systemctl','daemon-reload'],check=True)
        print('Manager service removed. Configuration, secrets and runtime data preserved.');return
    os.umask(0o077)
    directory.mkdir(parents=True,exist_ok=True);directory.chmod(0o700);os.chown(directory,0,0)
    if args.enable_lan:Configuration(directory,ROLE,repository=ROOT,prefix=prefix).enable_lan()
    code=prefix/'management';code.mkdir(parents=True,exist_ok=True)
    for name in ['manager','web','scripts']:
        shutil.copytree(ROOT/name,code/name,dirs_exist_ok=True,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    for name in ['ROLE','versions.lock.json']:shutil.copyfile(ROOT/name,code/name)
    for path in [code,*list(code.rglob('*'))]:path.chmod(0o755 if path.is_dir() else 0o644)
    (prefix/'releases').mkdir(exist_ok=True)
    unitpath.write_text(f'''[Unit]
Description=OpenPlayX {ROLE} configuration manager
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory={code}
ExecStart=/usr/bin/python3 {code}/manager/server.py --config-dir {directory} --runtime-prefix {prefix}
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ReadWritePaths={directory} {prefix}

[Install]
WantedBy=multi-user.target
''')
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','enable',unit],check=True)
    subprocess.run(['systemctl','restart',unit],check=True)
    subprocess.run(['systemctl','is-active','--quiet',unit],check=True)
    print('Installed '+('LAN-accessible Home' if ROLE=='home' else 'loopback-first Relay')+' manager. Read bootstrap-token in',directory,'if no administrator password has been set.')
if __name__=='__main__':main()
