#!/usr/bin/env python3
"""Role-scoped configuration API. Home permits authenticated LAN access."""
import argparse
import hashlib
import hmac
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import secrets
import ssl
import socket
import socketserver
import sys
import threading
import time

from configuration import Configuration, ConfigError, atomic, read, is_lan_address
from urllib.parse import urlsplit

ROOT=Path(__file__).resolve().parents[1]
ROLE=(ROOT/'ROLE').read_text().strip()

class Admin:
    def __init__(self,directory,now=time.time):
        self.directory=Path(directory);self.now=now;self.sessions={};self.failures={};self.lock=threading.Lock()
    def bootstrap(self,renew=False):
        path=self.directory/'bootstrap.json'
        if (self.directory/'admin.json').exists() and not renew:return
        if path.exists() and read(path)['expiresAt']>self.now() and not renew:return
        token=secrets.token_urlsafe(32)
        atomic(path,{'hash':hashlib.sha256(token.encode()).hexdigest(),'expiresAt':int(self.now()+900)})
        tokenfile=self.directory/'bootstrap-token'
        tokenfile.write_text(token+'\n');tokenfile.chmod(0o600)
    def authenticate(self,password,peer):
        if not isinstance(password,str) or len(password)>1024:raise ConfigError('loginFailed','登录失败。',401)
        with self.lock:
            recent=[t for t in self.failures.get(peer,[]) if t>self.now()-60]
            if len(recent)>=8:raise ConfigError('rateLimited','登录尝试过多，请稍后重试。',429)
            valid=False
            if (self.directory/'admin.json').exists():
                admin=read(self.directory/'admin.json')
                digest=hashlib.scrypt(password.encode(),salt=bytes.fromhex(admin['salt']),n=16384,r=8,p=1).hex()
                valid=hmac.compare_digest(digest,admin['hash'])
            if not valid and (self.directory/'bootstrap.json').exists():
                bootstrap=read(self.directory/'bootstrap.json')
                valid=bootstrap['expiresAt']>self.now() and hmac.compare_digest(bootstrap['hash'],hashlib.sha256(password.encode()).hexdigest())
            if not valid:
                self.failures[peer]=recent+[self.now()];raise ConfigError('loginFailed','凭据错误或初始化凭据已过期。',401)
            self.sessions={k:v for k,v in self.sessions.items() if v['expiresAt']>self.now()}
            token=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(32)
            self.sessions[token]={'csrf':csrf,'expiresAt':self.now()+1800}
            return token,csrf
    def session(self,token):
        with self.lock:
            session=self.sessions.get(token)
            if not session or session['expiresAt']<self.now():
                self.sessions.pop(token,None);raise ConfigError('authenticationRequired','请先登录管理页面。',401)
            return session
    def password(self,password):
        if not isinstance(password,str) or not 16<=len(password)<=256:raise ConfigError('weakPassword','管理员密码须为 16–256 个字符。')
        salt=secrets.token_bytes(16)
        digest=hashlib.scrypt(password.encode(),salt=salt,n=16384,r=8,p=1).hex()
        atomic(self.directory/'admin.json',{'salt':salt.hex(),'hash':digest})
        (self.directory/'bootstrap.json').unlink(missing_ok=True);(self.directory/'bootstrap-token').unlink(missing_ok=True)
        with self.lock:self.sessions.clear()

class Server(ThreadingHTTPServer):
    daemon_threads=True
    request_queue_size=32
    def __init__(self,store,management,address=None,now=time.time):
        self.store=store;self.management=management;self.admin=Admin(store.directory,now);self.admin.bootstrap();self._slots=threading.BoundedSemaphore(32)
        if ipaddress.ip_address((address or (management['listen'],management['port']))[0]).version==6:self.address_family=socket.AF_INET6
        super().__init__(address or (management['listen'],management['port']),Handler)
        self.scheme='https' if management['https'] else 'http'
        if management['https']:
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version=ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(store.tls_path(management['certificateFile']),store.tls_path(management['keyFile']))
            self.socket=context.wrap_socket(self.socket,server_side=True)
    def process_request(self,request,address):
        if not self._slots.acquire(blocking=False):self.shutdown_request(request);return
        try:super().process_request(request,address)
        except BaseException:self._slots.release();raise
    def process_request_thread(self,request,address):
        try:super().process_request_thread(request,address)
        finally:self._slots.release()
    def server_bind(self):
        # HTTPServer's default calls getfqdn(), causing an unrelated DNS lookup
        # and delaying even a loopback-only configuration page.
        socketserver.TCPServer.server_bind(self)
        self.server_name='OpenPlayX';self.server_port=self.server_address[1]
    @property
    def origins(self):
        port=self.server_address[1]
        return {self.scheme+'://'+('['+h+']' if ':'in h else h)+('' if port==({'http':80,'https':443}[self.scheme]) else ':'+str(port)) for h in self.management['allowedHosts']}

    def request_origins(self,peer,local,authority):
        origins=self.origins
        if ROLE!='home':return origins
        if not is_lan_address(peer) or not is_lan_address(local):raise ConfigError('lanOnly','Home 管理页只允许家庭局域网访问。',403)
        # Accept a literal IP only when it is the actual destination interface
        # of this connection. Never allow arbitrary Host values or LAN wildcards.
        try:
            url=urlsplit(authority)
            number=url.port or (443 if self.scheme=='https' else 80)
            if (not url.username and not url.password and not url.path and not url.query and not url.fragment
                and number==self.server_address[1] and ipaddress.ip_address(url.hostname)==ipaddress.ip_address(local)):
                origins=origins|{authority}
        except (ValueError,TypeError):pass
        return origins

class Handler(BaseHTTPRequestHandler):
    server_version='OpenPlayXManager'
    protocol_version='HTTP/1.1'
    def log_message(self,*args):pass # URLs, login fields and secrets never enter logs
    def setup(self):
        super().setup();self.connection.settimeout(10)
    def reply(self,status,value,headers=None,content_type='application/json; charset=utf-8'):
        data=json.dumps(value,ensure_ascii=False).encode() if content_type.startswith('application/json') else value
        self.send_response(status)
        for key,val in {'Content-Type':content_type,'Content-Length':str(len(data)),
          'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer',
          'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
          **(headers or {})}.items():self.send_header(key,val)
        self.end_headers();self.wfile.write(data)
    def origin(self,write=False):
        origin=self.headers.get('Origin')
        if len(self.headers.get_all('Host',[]))!=1:raise ConfigError('originDenied','Host 头无效。',403)
        authority=self.server.scheme+'://'+self.headers.get('Host','')
        origins=self.server.request_origins(self.client_address[0],self.connection.getsockname()[0],authority)
        if authority not in origins:raise ConfigError('originDenied','请求来源不允许。',403)
        if not write and self.path in ['/','/app.js','/style.css']:return
        if self.headers.get('Sec-Fetch-Site')=='cross-site':raise ConfigError('originDenied','请求来源不允许。',403)
        if (write and origin is None) or (origin is not None and (origin not in origins or (ROLE=='home' and origin!=authority))):raise ConfigError('originDenied','请求来源不允许。',403)
    def body(self):
        if self.headers.get('Transfer-Encoding') or self.headers.get('Content-Type','').split(';')[0]!='application/json':raise ConfigError('invalidRequest','请求必须是有长度的 JSON。',415)
        try:length=int(self.headers.get('Content-Length','0'))
        except ValueError:raise ConfigError('invalidRequest','请求长度无效。') from None
        if not 1<=length<=262144:raise ConfigError('invalidRequest','请求过大或为空。',413)
        try:
            raw=self.rfile.read(length)
            value=json.loads(raw)
            if len(raw)!=length or not isinstance(value,dict):raise ValueError()
            return value
        except (ValueError,UnicodeError):raise ConfigError('invalidRequest','JSON 无效。') from None
    def auth(self,write=False):
        cookie=SimpleCookie()
        try:cookie.load(self.headers.get('Cookie',''))
        except Exception:raise ConfigError('authenticationRequired','请重新登录。',401) from None
        self.token=cookie['opx_admin'].value if 'opx_admin'in cookie else ''
        session=self.server.admin.session(self.token)
        if write and not hmac.compare_digest(session['csrf'],self.headers.get('X-CSRF-Token','')):raise ConfigError('csrfDenied','会话校验失败，请重新登录。',403)
        return session
    def do_GET(self):self.handle_request(False)
    def do_POST(self):self.handle_request(True)
    def do_OPTIONS(self):self.reply(403,{'error':'originDenied','message':'不允许跨域访问。'})
    def handle_request(self,write):
        try:
            self.origin(write)
            if not write and self.path in ['/','/app.js','/style.css']:
                name={'/':'index.html','/app.js':'app.js','/style.css':'style.css'}[self.path]
                content=(ROOT/'web'/name).read_bytes()
                self.reply(200,content,content_type={'/':'text/html; charset=utf-8','/app.js':'text/javascript; charset=utf-8','/style.css':'text/css; charset=utf-8'}[self.path]);return
            data=self.body() if write else {}
            if write and self.path=='/api/login':
                token,csrf=self.server.admin.authenticate(data.get('password'),self.client_address[0])
                cookie='opx_admin='+token+'; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800'+('; Secure' if self.server.scheme=='https' else '')
                self.reply(200,{'csrfToken':csrf,'role':ROLE,'needsPassword':not(self.server.store.directory/'admin.json').exists()}, {'Set-Cookie':cookie});return
            session=self.auth(write)
            store=self.server.store
            if not write and self.path=='/api/session':
                self.reply(200,{'csrfToken':session['csrf'],'role':ROLE,'needsPassword':not(store.directory/'admin.json').exists()});return
            if write and self.path=='/api/password':
                self.server.admin.password(data.get('password'));self.reply(200,{'message':'管理员密码已设置，所有会话已退出。请重新登录。'});return
            if write and self.path=='/api/logout':
                with self.server.admin.lock:self.server.admin.sessions.pop(self.token,None)
                self.reply(200,{}, {'Set-Cookie':'opx_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'});return
            if not write and self.path in ['/api/config','/api/export']:
                cfg=store.load()
                self.reply(200,{'config':cfg,'role':ROLE,'tlsFiles':sorted(str(p.relative_to(store.directory)) for p in (store.directory/'tls').glob('*') if p.is_file() and not p.is_symlink()),
                  'grants':read(store.directory/'grants.json') if ROLE=='home' and (store.directory/'grants.json').exists() else None});return
            if not write and self.path=='/api/recovery':
                self.reply(200,store.recovery_info());return
            if write and self.path=='/api/recover':
                self.reply(200,{'config':store.recover(data.get('fileHash')),'message':'原文件已另存保留，备份已恢复为新修订，尚未应用。'});return
            if not write and self.path=='/api/status':
                self.reply(200,{**store.status(),'managementRestartRequired':store.load()['management']!=self.server.management});return
            if write and self.path=='/api/tls':
                self.reply(200,{'file':store.import_tls(data.get('kind'),data.get('content'))});return
            if write and self.path=='/api/validate':
                cfg,_=store._prepare(data.get('config'),data.get('secrets',{}));self.reply(200,{'draftRevision':cfg['revision'],'valid':True});return
            if write and self.path=='/api/test':
                self.reply(200,store.test(data.get('config'),data.get('secrets',{})));return
            if write and self.path=='/api/save':
                cfg=store.save(data.get('config'),data.get('expectedRevision'),data.get('secrets',{}));self.reply(200,{'config':cfg,'message':'配置已保存，尚未应用。'});return
            if write and self.path=='/api/apply':
                cfg=store.load()
                if cfg['management']!=self.server.management:raise ConfigError('managementRestartRequired','管理入口变化需要先保存，再在本机重启管理服务后应用。当前运行修订保持不变。',409)
                self.reply(200,store.apply(data.get('expectedRevision')));return
            if write and self.path=='/api/restore':
                self.reply(200,{'config':store.restore(data.get('expectedRevision')),'message':'旧配置已保存为新修订，尚未应用。'});return
            raise ConfigError('notFound','接口不存在。',404)
        except ConfigError as error:self.reply(error.status,{'error':error.code,'message':str(error)})
        except (OSError,ValueError,TypeError,KeyError,AttributeError):self.reply(400,{'error':'invalidRequest','message':'操作失败，请检查配置和服务权限；原文件未被默认值覆盖。'})
        except Exception:self.reply(500,{'error':'operationFailed','message':'操作失败；请检查本机组件状态。机密未写入日志。'})


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config-dir',type=Path,default=Path('/var/lib/openplayx-'+ROLE))
    parser.add_argument('--bin-dir',type=Path)
    parser.add_argument('--runtime-prefix',type=Path)
    parser.add_argument('--import-legacy',type=Path,help='Local-only initial import; never overwrites existing JSON')
    parser.add_argument('--home-id')
    parser.add_argument('--renew-bootstrap',action='store_true')
    parser.add_argument('--enable-lan',action='store_true',help='Home only: explicitly save LAN management access for an existing configuration')
    args=parser.parse_args();os.umask(0o077)
    store=Configuration(args.config_dir,ROLE,binaries=args.bin_dir,prefix=args.runtime_prefix)
    if args.import_legacy:
        store.import_legacy(args.import_legacy,args.home_id)
        print('Imported into',store.path,'; not applied.');return
    if args.enable_lan:
        if ROLE!='home':parser.error('--enable-lan is only supported by Home')
        cfg=store.enable_lan();print('Saved Home LAN management access on port',cfg['management']['port'],'; restart the manager service to use it.');return
    admin=Admin(store.directory);admin.bootstrap(args.renew_bootstrap)
    if args.renew_bootstrap:print('Renewed local bootstrap credential file; expires in 15 minutes.');return
    try:
        cfg=store.load();management=cfg['management']
        if ROLE=='home':store.validate_management(management)
        elif not ipaddress.ip_address(management['listen']).is_loopback:store.validate(cfg,store.secrets())
    except (ConfigError,KeyError,TypeError,ValueError):
        # Recovery uses a fixed safe loopback listener, never guessed public
        # settings, and never writes defaults over the unrecognized file.
        management={**store.blank()['management'],'listen':'127.0.0.1'}
        print('Configuration unavailable; using authenticated loopback recovery. Original files preserved.')
    server=Server(store,management)
    print('OpenPlayX',ROLE,'manager:',server.scheme+'://'+management['listen']+':'+str(management['port']))
    if ROLE=='home' and management['listen'] in ['0.0.0.0','::']:print('LAN access:',server.scheme+'://<Home LAN IP>:'+str(management['port']))
    if (store.directory/'bootstrap-token').exists():print('Read local bootstrap-token in the private config directory to sign in (15 minute expiry).')
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:server.server_close()
if __name__=='__main__':
    try:main()
    except ConfigError as error:print(error.code+': '+str(error),file=sys.stderr);sys.exit(1)
