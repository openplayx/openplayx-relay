#!/usr/bin/env python3
"""Create one-household config and pairing bundles, without replacing secrets."""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import uuid

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--host', required=True)
p.add_argument('--tls-name', required=True)
p.add_argument('--certificate', type=Path, required=True)
p.add_argument('--key', type=Path, required=True)
p.add_argument('--proxy-ca', type=Path, help='Optional private CA for proxy TLS')
p.add_argument('--output', type=Path, default=Path('secrets'))
p.add_argument('--port', type=int, default=443)
a=p.parse_args()
os.umask(0o077)
a.output.mkdir(mode=0o700)  # fail if it exists; never rotate credentials implicitly
root=a.output.resolve()
def write(name,value):
 path=root/name
 path.write_text(json.dumps(value,indent=2)+'\n');path.chmod(0o600)
subprocess.run(['openssl','req','-x509','-newkey','rsa:3072','-nodes','-days','365',
 '-subj','/CN=openplayx-frps','-addext','subjectAltName=DNS:openplayx-frps',
 '-keyout',str(root/'frps.key'),'-out',str(root/'frps.crt')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
# A dedicated self-signed frps server certificate is the home trust anchor.
# Proxy TLS uses the explicitly supplied certificate, never this frps identity.
proxy={'host':a.host,'port':a.port,'serverName':a.tls_name,'appUUID':str(uuid.uuid4()),'homeUUID':str(uuid.uuid4()),
 'certificatePath':str(a.certificate.resolve()),'keyPath':str(a.key.resolve())}
if a.proxy_ca: proxy['caCertificate']=a.proxy_ca.read_text()
token=secrets.token_urlsafe(48)
service={'id':'jellyfin','remotePort':18096}
write('deployment.json',{'proxy':proxy,'frpToken':token,'controlPort':7000,'services':[service],
 'frpCertificatePath':str(root/'frps.crt'),'frpKeyPath':str(root/'frps.key')})
homeproxy={k:v for k,v in proxy.items() if k not in ['appUUID','certificatePath','keyPath']}
write('home.json',{'proxy':homeproxy,'frpToken':token,'controlPort':7000,'socksPort':1080,
 'frpServerName':'openplayx-frps','frpCAPath':str(root/'frps.crt'),
 'services':[{**service,'localHost':'192.168.50.10','localPort':8096}]})
tls={'enabled':True,'server_name':a.tls_name}
if a.proxy_ca: tls['certificate']=a.proxy_ca.read_text()
write('app-jellyfin.json',{'version':1,'lineId':str(uuid.uuid4()),'homeId':str(uuid.uuid4()),'serviceId':'jellyfin',
 'remotePort':18096,'remoteAddress':'http://jellyfin.home.invalid:8096',
 'outbound':{'type':'vless','server':a.host,'server_port':a.port,'uuid':proxy['appUUID'],'tls':tls}})
print('Created private deployment, home and App pairing files in',root)
