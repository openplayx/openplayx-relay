#!/usr/bin/env python3
"""Real TLS/VLESS + SOCKS/frp + embedded bridge integration; no VPS required."""
import argparse
import ctypes
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import uuid

p=argparse.ArgumentParser()
p.add_argument('--bin',type=Path,required=True)
p.add_argument('--home',type=Path,default=Path(__file__).resolve().parents[2]/'openplayx-home')
p.add_argument('--app-library',type=Path,required=True)
a=p.parse_args(); a.bin=a.bin.resolve()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
relay=load('relay',Path(__file__).resolve().parents[1]/'scripts/manage.py')
home=load('home',a.home/'scripts/manage.py')
def freeport():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
class Media(BaseHTTPRequestHandler):
 def do_GET(self):
  assert self.headers.get('Range')=='bytes=3-7'
  assert self.headers.get('Authorization')=='Bearer media-secret'
  assert self.headers.get('Host')=='nas.example:8096'
  self.send_response(206);self.send_header('Content-Range','bytes 3-7/10');self.send_header('Content-Length','5');self.end_headers();self.wfile.write(b'34567')
 def log_message(self,*args):pass
server=ThreadingHTTPServer(('127.0.0.1',0),Media)
threading.Thread(target=server.serve_forever,daemon=True).start()
processes=[]
lib=ctypes.CDLL(str(a.app_library.resolve()))
lib.opx_remote_start.argtypes=[ctypes.c_char_p];lib.opx_remote_start.restype=ctypes.c_int
lib.opx_remote_stop.argtypes=[ctypes.c_int]
def start(*args):
 proc=subprocess.Popen([str(x) for x in args],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);processes.append(proc);return proc
handles=[]
def bridge(out,port):
 value=lib.opx_remote_start(json.dumps({'outbound':out,'targetPort':port}).encode());assert value>0,'bridge start failed';handles.append(value);return value
def fetch(port):
 c=http.client.HTTPConnection('127.0.0.1',port,timeout=3)
 try:
  c.request('GET','/video',headers={'Range':'bytes=3-7','Authorization':'Bearer media-secret','Host':'nas.example:8096'})
  r=c.getresponse();assert r.status==206 and r.getheader('Content-Range')=='bytes 3-7/10';assert r.read()==b'34567'
 finally:c.close()
def denied(out,port):
 number=bridge(out,port)
 with socket.create_connection(('127.0.0.1',number),timeout=3) as s:
  s.settimeout(3);s.sendall(b'GET / HTTP/1.0\r\n\r\n')
  try:assert not s.recv(1),'unauthorized port returned data'
  except (ConnectionResetError,BrokenPipeError):pass
try:
 with tempfile.TemporaryDirectory(prefix='openplayx-e2e-') as temp:
  root=Path(temp);cert=root/'tls.crt';key=root/'tls.key'
  subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  proxyport,control,mapping,socks=[freeport() for _ in range(4)]
  cfg={'proxy':{'host':'127.0.0.1','port':proxyport,'serverName':'localhost','appUUID':str(uuid.uuid4()),'homeUUID':str(uuid.uuid4()),'certificatePath':str(cert),'keyPath':str(key),'caCertificate':cert.read_text()},'frpToken':'integration-test-token-'*3,'controlPort':control,'services':[{'id':'jellyfin','remotePort':mapping}],'frpCertificatePath':str(cert),'frpKeyPath':str(key)}
  h=json.loads(json.dumps(cfg));h.update({'socksPort':socks,'frpCAPath':str(cert),'frpServerName':'localhost'})
  h['services'][0].update(localHost='127.0.0.1',localPort=server.server_port)
  relay.render(cfg,root/'relay');home.render(h,root/'home')
  relay.check(root/'relay',a.bin);home.check(root/'home',a.bin)
  start(a.bin/'frps','-c',root/'relay/frps.toml')
  start(a.bin/'sing-box','run','-c',root/'relay/sing-box.json')
  home_sing=start(a.bin/'sing-box','run','-c',root/'home/sing-box.json')
  home.wait_socks(socks)
  start(a.bin/'frpc','-c',root/'home/frpc.toml')
  out=relay.outbound(cfg,'app');out.pop('tag')
  number=bridge(out,mapping)
  for attempt in range(40):
   try:fetch(number);break
   except (OSError,http.client.HTTPException,AssertionError):
    if attempt==39:raise
    time.sleep(.25)
  print('PASS real embedded VLESS -> relay -> frp -> home -> authenticated Range media')
  denied(out,control)
  denied(out,server.server_port)
  denied(relay.outbound(cfg,'home'),mapping)
  unknown={**out,'uuid':str(uuid.uuid4())};denied(unknown,mapping)
  print('PASS App/home account separation, unallocated ports and unknown identity denied')
  home_sing.terminate();home_sing.wait(timeout=5)
  time.sleep(1)
  try:fetch(number)
  except (OSError,http.client.HTTPException):print('PASS home proxy stopped: no direct frpc fallback')
  else:raise AssertionError('media remained reachable after home proxy stopped')
finally:
 for number in handles:lib.opx_remote_stop(number)
 for proc in processes:
  if proc.poll() is None:proc.terminate()
 for proc in processes:
  try:proc.wait(timeout=5)
  except subprocess.TimeoutExpired:proc.kill();proc.wait()
 server.shutdown();server.server_close()
