"""Authoritative logical JSON configuration. No browser-supplied file paths."""
import contextlib
import copy
import fcntl
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import hashlib
import subprocess
import tempfile
import time
import uuid

class ConfigError(Exception):
    def __init__(self, code, message, status=400):
        super().__init__(message)
        self.code, self.status = code, status

def atomic(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix='.'+path.name+'-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        os.chmod(name, 0o600)
        os.replace(name, path)
        descriptor = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
    finally:
        if os.path.exists(name): os.unlink(name)

def read(path):
    try:
        with Path(path).open() as stream: return json.load(stream)
    except (ValueError, OSError) as exc:
        raise ConfigError('invalidFile', '配置文件损坏或不可读，原文件已保留。', 409) from exc

def keys(value, allowed, required=()):
    if not isinstance(value, dict) or set(value)-set(allowed) or set(required)-set(value):
        raise ConfigError('invalidFields', '配置字段缺失或包含未知字段。')

def text(value, field):
    if not isinstance(value, str) or not value.strip() or len(value)>256 or any(ord(c)<32 for c in value):
        raise ConfigError('invalidField', field+' 无效。')
    return value

def port(value):
    if type(value) is not int or not 1<=value<=65535: raise ConfigError('invalidPort', '端口须为 1–65535。')
    return value

def host(value):
    text(value,'主机')
    try: ipaddress.ip_address(value)
    except ValueError:
        if len(value)>253 or any(not(c.isascii() and (c.isalnum() or c in '.-')) for c in value):
            raise ConfigError('invalidHost','请输入 IP 或主机名，不包含 URL、路径或凭据。')
    return value

def identifier(value):
    text(value,'ID')
    if any(not(c.isascii() and (c.isalnum() or c in '-_')) for c in value):
        raise ConfigError('invalidId','ID 仅支持字母、数字、短横线、下划线。')
    return value

# Explicit LAN ranges; is_private also includes reserved/documentation addresses.
def is_lan_address(value):
    try:
        address=ipaddress.ip_address(value)
        if isinstance(address,ipaddress.IPv6Address) and address.ipv4_mapped:address=address.ipv4_mapped
        return address.is_loopback or any(address in ipaddress.ip_network(network) for network in [
            '10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','169.254.0.0/16','fc00::/7','fe80::/10'])
    except (ValueError,TypeError):return False

class Configuration:
    def __init__(self, directory, role, repository=None, binaries=None, prefix=None, controller=None):
        self.directory=Path(directory).resolve(); self.role=role
        self.repository=Path(repository or Path(__file__).resolve().parents[1]).resolve()
        self.binaries=Path(binaries or '/opt/openplayx-'+role+'/current/bin').absolute()
        self.prefix=Path(prefix or '/opt/openplayx-'+role).absolute()
        self.controller=controller or self._control
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path=self.directory/(role+'.json')
        spec=importlib.util.spec_from_file_location('deploy_'+role,self.repository/'scripts/manage.py')
        self.deploy=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.deploy)
        self.deploy.ROLE=role;self.deploy.FRP='frps' if role=='relay' else 'frpc'

    @contextlib.contextmanager
    def lock(self):
        with (self.directory/'.lock').open('a') as lock:
            os.chmod(self.directory/'.lock',0o600)
            fcntl.flock(lock,fcntl.LOCK_EX)
            try: yield
            finally: fcntl.flock(lock,fcntl.LOCK_UN)

    def blank(self):
        common={'schemaVersion':1,'revision':0,'homeId':'home-main',
          'proxy':{'host':'relay.example.com','port':443,'serverName':'relay.example.com','protocol':'vless-tls','homeCredentialRef':''},
          'frp':{'controlPort':7000,'credentialRef':'','serverName':'openplayx-frps'},
          'services':[], 'log':{'level':'warn'},
          'management':{'listen':'127.0.0.1' if self.role=='relay' else '0.0.0.0','port':9081 if self.role=='relay' else 9080,'https':False,'allowedHosts':['localhost','127.0.0.1']}}
        if self.role=='relay':
            common['proxy'].update(appCredentialRef='',listen='0.0.0.0',certificateFile='',keyFile='')
            common['frp'].update(certificateFile='',keyFile='')
        else:
            common['proxy']['caCertificate']=''
            common['singBox']={'socksListen':'127.0.0.1','socksPort':1080}
            common['frp']['caFile']=''
            common['reconnect']={'intervalSeconds':5}
        return common

    def load(self):
        if not self.path.exists(): return self.blank()
        value=read(self.path)
        if not isinstance(value,dict) or value.get('schemaVersion')!=1: raise ConfigError('unknownSchema','配置版本不支持，禁止覆盖原文件。',409)
        template=self.blank();keys(value,set(template),set(template))
        for section in ['proxy','frp','log']+(['singBox','reconnect'] if self.role=='home' else []):
            keys(value[section],set(template[section]),set(template[section]))
        keys(value['management'],{'listen','port','https','allowedHosts','certificateFile','keyFile'},{'listen','port','https','allowedHosts'})
        if not isinstance(value['services'],list):raise ConfigError('invalidFields','服务配置无效，原文件已保留。',409)
        for service in value['services']:
            fields={'serviceId','relayPort'}|({'targetHost','targetPort'} if self.role=='home' else set())
            keys(service,fields,fields)
        for owner in [value['proxy'],value['frp']]:
            for key,ref in owner.items():
                if (key.endswith('CredentialRef') or key=='credentialRef') and (not isinstance(ref,str) or (ref and not ref.startswith('secret:'))):
                    raise ConfigError('plainSecretDenied','普通配置只能保存机密引用，原文件已保留。',409)
        if 'PRIVATE KEY' in str(value['proxy'].get('caCertificate','')):raise ConfigError('plainSecretDenied','CA 字段不能包含私钥，原文件已保留。',409)
        return value

    def secrets(self):
        return read(self.directory/'secrets.json') if (self.directory/'secrets.json').exists() else {}

    def tls_path(self, name):
        # An API may refer only to already installed TLS assets. No relative
        # traversal, arbitrary host paths, symlinks or file download endpoint.
        if not isinstance(name,str) or not name.startswith('tls/') or len(Path(name).parts)!=2:
            raise ConfigError('invalidCertificate','请选择已经导入的 TLS 文件。')
        path=self.directory/name
        if path.is_symlink() or path.parent.is_symlink() or not path.is_file() or path.resolve().parent != self.directory/'tls':
            raise ConfigError('invalidCertificate','TLS 文件不存在或超出受控目录。')
        return path

    def validate(self,cfg,values,allow_empty=False):
        allowed=set(self.blank())
        keys(cfg,allowed,allowed)
        if cfg['schemaVersion']!=1 or type(cfg['revision']) is not int or cfg['revision']<0:
            raise ConfigError('unknownSchema','不支持的 schemaVersion 或 revision。')
        identifier(cfg['homeId'])
        p=cfg['proxy']; pkeys=set(self.blank()['proxy'])
        keys(p,pkeys,pkeys); host(p['host']);port(p['port']);host(p['serverName'])
        if p['protocol']!='vless-tls':raise ConfigError('invalidProtocol','当前管理器使用 VLESS + TLS 配置模板。')
        f=cfg['frp'];keys(f,set(self.blank()['frp']),set(self.blank()['frp']));port(f['controlPort']);host(f['serverName'])
        if p['port']==f['controlPort']:raise ConfigError('portConflict','代理和 frps 控制端口冲突。')
        refs=[(p,'homeCredentialRef','uuid'),(f,'credentialRef','token')]
        if self.role=='relay':
            host(p['listen']);refs.append((p,'appCredentialRef','uuid'))
            for owner,key in [(p,'certificateFile'),(p,'keyFile'),(f,'certificateFile'),(f,'keyFile')]:self.tls_path(owner[key])
        else:
            keys(cfg['singBox'],{'socksListen','socksPort'},{'socksListen','socksPort'})
            if cfg['singBox']['socksListen']!='127.0.0.1':raise ConfigError('mandatoryProxy','家庭 SOCKS 必须只监听回环。')
            port(cfg['singBox']['socksPort']);self.tls_path(f['caFile'])
            keys(cfg['reconnect'],{'intervalSeconds'},{'intervalSeconds'})
            if type(cfg['reconnect']['intervalSeconds'])is not int or not 1<=cfg['reconnect']['intervalSeconds']<=60:raise ConfigError('invalidReconnect','重试间隔须为 1–60 秒。')
            if not isinstance(p['caCertificate'],str) or len(p['caCertificate'])>32768 or 'PRIVATE KEY' in p['caCertificate']:raise ConfigError('invalidCA','CA 内容过大。')
        for owner,key,kind in refs:
            ref=owner[key]
            if not isinstance(ref,str) or not ref.startswith('secret:') or ref not in values:raise ConfigError('missingSecret','请设置必需的连接凭据。')
            value=values[ref]
            try:
                if kind=='uuid':uuid.UUID(value)
                elif not isinstance(value,str) or len(value)<32 or len(value)>4096:raise ValueError()
            except (ValueError,TypeError,AttributeError):raise ConfigError('invalidSecret','UUID 或 frp token 格式无效。') from None
        if self.role=='relay' and values[p['homeCredentialRef']]==values[p['appCredentialRef']]:raise ConfigError('sharedIdentity','App 与家庭端必须使用不同身份。')
        keys(cfg['log'],{'level'},{'level'})
        if cfg['log']['level'] not in ['warn','error','info']:raise ConfigError('invalidLog','日志级别无效。')
        m=cfg['management'];self.validate_management(m)
        used=[p['port'],f['controlPort'],m['port']]
        if self.role=='home':used.append(cfg['singBox']['socksPort'])
        if len(set(used))!=len(used):raise ConfigError('portConflict','组件与管理监听端口冲突。')
        if not isinstance(cfg['services'],list) or not 1<=len(cfg['services'])<=32:raise ConfigError('invalidServices','请明确配置 1–32 个服务。')
        names=set();numbers=set()
        grants=read(self.directory/'grants.json') if self.role=='home' else None
        if grants and (grants['homeId']!=cfg['homeId'] or grants['relayHost']!=p['host'] or grants['relayPort']!=p['port']):raise ConfigError('grantMismatch','家庭或 relay 与已导入授权不匹配，请在本机重新导入可信授权。')
        for item in cfg['services']:
            fields={'serviceId','relayPort'}|({'targetHost','targetPort'} if self.role=='home' else set())
            keys(item,fields,fields);identifier(item['serviceId']);number=port(item['relayPort'])
            if item['serviceId']in names or number in numbers or number in used:raise ConfigError('portConflict','服务引用或映射端口重复，或与组件监听冲突。')
            names.add(item['serviceId']);numbers.add(number)
            if self.role=='home':
                host(item['targetHost']);port(item['targetPort'])
                if not grants or [item['serviceId'],number] not in grants['services']:raise ConfigError('unauthorizedMapping','映射未获 Relay 授权；Home 页面不能扩大映射范围。')
                if item['targetHost'] in ['127.0.0.1','localhost','::1'] and item['targetPort'] in used:raise ConfigError('targetConflict','家庭服务不能指向本机管理或代理端口。')
        return cfg

    def validate_management(self,m):
        keys(m,{'listen','port','https','allowedHosts','certificateFile','keyFile'},{'listen','port','https','allowedHosts'})
        try:listen=ipaddress.ip_address(m['listen'])
        except ValueError:raise ConfigError('invalidListen','管理监听地址须为明确的 IP。') from None
        port(m['port'])
        if type(m['https']) is not bool or not isinstance(m['allowedHosts'],list) or not 1<=len(m['allowedHosts'])<=10:raise ConfigError('invalidManagement','管理页面配置无效。')
        for name in m['allowedHosts']:host(name)
        if m['https']:
            self.tls_path(m.get('certificateFile'));self.tls_path(m.get('keyFile'))
        if self.role=='home':
            if not (listen.is_unspecified or is_lan_address(listen)):raise ConfigError('lanOnly','Home 管理页仅允许回环或家庭局域网监听。')
        elif not listen.is_loopback:
            if not (self.directory/'admin.json').exists():raise ConfigError('adminRequired','非回环管理必须先设置管理员密码。')
            if (self.role=='relay' or not listen.is_private) and not m['https']:raise ConfigError('httpsRequired','Relay 或公网管理必须开启 HTTPS。')

    def materialize(self,cfg,values):
        self.validate(cfg,values)
        p,f=cfg['proxy'],cfg['frp']
        proxy={'host':p['host'],'port':p['port'],'serverName':p['serverName'],'homeUUID':values[p['homeCredentialRef']]}
        result={'proxy':proxy,'frpToken':values[f['credentialRef']],'controlPort':f['controlPort'],'logLevel':cfg['log']['level'],
          'services':[{'id':s['serviceId'],'remotePort':s['relayPort'],**({'localHost':s['targetHost'],'localPort':s['targetPort']} if self.role=='home' else {})} for s in cfg['services']]}
        if self.role=='relay':
            proxy.update(appUUID=values[p['appCredentialRef']],certificatePath=str(self.tls_path(p['certificateFile'])),keyPath=str(self.tls_path(p['keyFile'])))
            result.update(listen=p['listen'],frpCertificatePath=str(self.tls_path(f['certificateFile'])),frpKeyPath=str(self.tls_path(f['keyFile'])))
        else:
            proxy['caCertificate']=p['caCertificate']
            result.update(socksPort=cfg['singBox']['socksPort'],frpServerName=f['serverName'],frpCAPath=str(self.tls_path(f['caFile'])))
        return result

    def import_tls(self,kind,content):
        if kind not in ['certificate','privateKey'] or not isinstance(content,str) or not 1<=len(content)<=131072:
            raise ConfigError('invalidTLS','请选择 PEM 证书或未加密私钥，最多 128 KiB。')
        directory=self.directory/'tls';directory.mkdir(exist_ok=True,mode=0o700)
        if len(list(directory.iterdir()))>=128:raise ConfigError('tlsQuota','TLS 文件数量已达上限，请在本机整理旧资产。',409)
        digest=hashlib.sha256(content.encode()).hexdigest()
        name=digest+('.crt' if kind=='certificate' else '.key')
        with tempfile.NamedTemporaryFile(mode='w',dir=directory,delete=False) as temp:
            temp.write(content);filename=Path(temp.name)
        try:
            filename.chmod(0o600)
            if kind=='certificate':ssl.PEM_cert_to_DER_cert(content)
            else:subprocess.run(['openssl','pkey','-in',str(filename),'-passin','pass:','-noout','-check'],check=True,timeout=5,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            os.replace(filename,directory/name)
        except (ValueError,OSError,subprocess.SubprocessError):raise ConfigError('invalidTLS','TLS 文件格式无效，私钥须为未加密 PEM。') from None
        finally:filename.unlink(missing_ok=True)
        return 'tls/'+name

    def _prepare(self,cfg,updates):
        cfg=copy.deepcopy(cfg);values=self.secrets()
        keys(updates,{'homeUUID','appUUID','frpToken'})
        fields={'homeUUID':(cfg['proxy'],'homeCredentialRef'),'frpToken':(cfg['frp'],'credentialRef')}
        if self.role=='relay':fields['appUUID']=(cfg['proxy'],'appCredentialRef')
        for field,value in updates.items():
            if field not in fields:raise ConfigError('invalidSecret','此端不支持该机密字段。')
            if value is None:continue # untouched
            owner,key=fields[field]
            if value=='':owner[key]='' # explicit clear; required references fail validation
            else:
                ref='secret:'+secrets.token_hex(16);values[ref]=value;owner[key]=ref
        self.validate(cfg,values)
        return cfg,values

    def save(self,cfg,expected,updates=None):
        with self.lock():
            old=self.load()
            if type(expected)is not int or expected!=old['revision']:raise ConfigError('conflict','配置已修改，请重新加载后编辑。',409)
            if cfg.get('revision')!=expected:raise ConfigError('conflict','草稿修订不匹配。',409)
            cfg,values=self._prepare(cfg,updates or {})
            clock_path=self.directory/'revision.json'
            clock=read(clock_path)['lastIssuedRevision'] if clock_path.exists() else expected
            if type(clock)is not int or clock<0:raise ConfigError('invalidRevision','修订元数据损坏，已保留原文件。',409)
            cfg['revision']=max(expected,clock)+1
            atomic(clock_path,{'lastIssuedRevision':cfg['revision']})
            prior=self.secrets()
            atomic(self.directory/'secrets.json',values) # new secrets first
            try:
                if self.path.exists():atomic(self.directory/(self.role+'.backup.json'),old)
                atomic(self.path,cfg)
            except BaseException:
                # A successful config write followed by a directory fsync error
                # must not discard keys now referenced by the authoritative file.
                try: committed=self.path.exists() and read(self.path)==cfg
                except ConfigError:committed=False
                if not committed:atomic(self.directory/'secrets.json',prior)
                raise
            return cfg

    def test(self,cfg,updates=None):
        cfg,values=self._prepare(cfg,updates or {})
        revision=cfg['revision']
        with tempfile.TemporaryDirectory(prefix='.test-',dir=self.directory) as folder:
            runtime=Path(folder)
            try:
                self.render(cfg,values,runtime)
                self.deploy.check(runtime,self.binaries)
            except (OSError,ValueError,subprocess.SubprocessError):raise ConfigError('componentCheckFailed','组件配置校验失败；请检查证书、凭据与固定版本二进制。') from None
        # Connect to only this explicitly configured proxy endpoint, no credentials
        # or media requests are sent and no production component is restarted.
        reachable=False
        if self.role=='home':
            try:
                with socket.create_connection((cfg['proxy']['host'],cfg['proxy']['port']),timeout=2):reachable=True
            except OSError:pass
        return {'draftRevision':revision,'configValid':True,'relayTcpReachable':reachable if self.role=='home' else None,
          'message':'组件配置已通过；TCP 可达不等于代理认证、家庭隧道或媒体播放成功。'}

    def render(self,cfg,values,output):
        self.deploy.render(self.materialize(cfg,values),output)
        sing=read(output/'sing-box.json');sing['log']['level']=cfg['log']['level'];atomic(output/'sing-box.json',sing)
        frp=output/('frps.toml' if self.role=='relay' else 'frpc.toml')
        content=frp.read_text().replace('log.level = "warn"','log.level = '+json.dumps(cfg['log']['level']))
        frp.write_text(content);frp.chmod(0o600)

    def _control(self,action,cfg):
        names=['sing-box','frps' if self.role=='relay' else 'frpc']
        for name in names:
            for attempt in range(3 if self.role=='home' and action=='restart' else 1):
                try:
                    subprocess.run(['systemctl',action,f'openplayx-{self.role}-{name}.service'],check=True,timeout=35,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                    break
                except subprocess.SubprocessError:
                    if attempt==2 or self.role!='home' or action!='restart':raise
                    time.sleep(cfg['reconnect']['intervalSeconds'])
            if self.role=='home' and name=='sing-box' and action=='restart':self.deploy.wait_socks(cfg['singBox']['socksPort'])
        if action=='restart':
            for name in names:subprocess.run(['systemctl','is-active','--quiet',f'openplayx-{self.role}-{name}.service'],check=True,timeout=5)

    def status(self):
        state=read(self.directory/'status.json') if (self.directory/'status.json').exists() else {'appliedRevision':None,'error':None}
        if not isinstance(state,dict) or set(state)-{'appliedRevision','error','appliedAt','failedRevision'} or 'appliedRevision' not in state or (state['appliedRevision'] is not None and type(state['appliedRevision'])is not int) or state.get('error') not in [None,'applyFailed','stateRecovered','legacyRuntimeRolledBack']:raise ConfigError('invalidState','运行状态文件损坏，原文件已保留。',409)
        cfg=self.load()
        components={}
        for name in ['sing-box','frps' if self.role=='relay' else 'frpc']:
            try:
                result=subprocess.run(['systemctl','is-active',f'openplayx-{self.role}-{name}.service'],capture_output=True,timeout=3)
                components[name]='active' if result.returncode==0 else 'inactive'
            except (OSError,subprocess.SubprocessError):components[name]='unavailable'
        return {**state,'desiredRevision':cfg['revision'],'components':components,'savedIsApplied':state['appliedRevision']==cfg['revision']}

    def apply(self,expected):
        with self.lock():
            cfg=self.load()
            if expected!=cfg['revision']:raise ConfigError('conflict','配置已修改，未应用其他修订。',409)
            self.validate(cfg,self.secrets())
            state=read(self.directory/'status.json') if (self.directory/'status.json').exists() else {'appliedRevision':None,'error':None}
            release=self.prefix/'releases'/('managed-'+str(time.time_ns()))
            old=(self.prefix/'current').resolve() if (self.prefix/'current').exists() else None
            switched=False
            try:
                (release/'config').mkdir(parents=True,mode=0o700)
                # Fixed binaries only; never download or execute a browser path.
                for component in ['sing-box','frps' if self.role=='relay' else 'frpc']:
                    (release/'bin').mkdir(exist_ok=True)
                    shutil.copy2(self.binaries/component,release/'bin'/component)
                self.render(cfg,self.secrets(),release/'config')
                self.deploy.check(release/'config',release/'bin')
                atomic(release/'logical.json',cfg)
                if os.geteuid()==0:
                    import grp
                    self.deploy.restrict_release(self.prefix,release,grp.getgrnam('openplayx-'+self.role).gr_gid)
                    # TLS assets stay in the private manager directory. Copy
                    # only referenced assets to this release for DynamicUser.
                self._runtime_tls(release)
                link=self.prefix/'.next';link.unlink(missing_ok=True);link.symlink_to(release);os.replace(link,self.prefix/'current');switched=True
                self.controller('restart',cfg)
                if old:
                    previous=self.prefix/'previous';previous.unlink(missing_ok=True);previous.symlink_to(old)
                atomic(self.directory/'last-good.json',cfg)
                atomic(self.directory/'status.json',{'appliedRevision':cfg['revision'],'error':None,'appliedAt':int(time.time())})
                self._collect_secrets()
                return {'appliedRevision':cfg['revision'],'error':None}
            except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError,ConfigError):
                if switched:
                    if old:
                        link=self.prefix/'.restore';link.unlink(missing_ok=True);link.symlink_to(old);os.replace(link,self.prefix/'current')
                        try:self.controller('restart',read(self.directory/'last-good.json'))
                        except (OSError,KeyError,TypeError,subprocess.SubprocessError,ConfigError):pass
                    else:
                        try:self.controller('stop',cfg)
                        except (OSError,subprocess.SubprocessError):pass
                        (self.prefix/'current').unlink(missing_ok=True)
                atomic(self.directory/'status.json',{**state,'error':'applyFailed','failedRevision':cfg['revision']})
                raise ConfigError('applyFailed','配置已保存但未生效；已尝试恢复上一份运行配置。',409) from None

    def _runtime_tls(self,release):
        # Derived configs must reference certificate copies readable by the
        # component account, never grant it access to secrets.json/admin.json.
        destination=release/'config/tls';destination.mkdir(mode=0o750,exist_ok=True)
        sing=read(release/'config/sing-box.json')
        def copy_path(value):
            original=Path(value)
            if original.resolve().parent!=self.directory/'tls':raise ConfigError('invalidCertificate','运行证书超出受控目录。')
            path=destination/original.name;shutil.copyfile(original,path);path.chmod(0o640);return str(path)
        if self.role=='relay':
            for entry in sing['inbounds']:
                for key in ['certificate_path','key_path']:entry['tls'][key]=copy_path(entry['tls'][key])
        atomic(release/'config/sing-box.json',sing)
        filename=release/'config'/('frps.toml' if self.role=='relay' else 'frpc.toml')
        content=filename.read_text()
        # Only generator-owned exact TOML fields are replaced.
        fields=['transport.tls.certFile','transport.tls.keyFile'] if self.role=='relay' else ['transport.tls.trustedCaFile']
        for field in fields:
            lines=content.splitlines()
            for index,line in enumerate(lines):
                if line.startswith(field+' = '):lines[index]=field+' = '+json.dumps(copy_path(json.loads(line.split(' = ',1)[1])))
            content='\n'.join(lines)+'\n'
        filename.write_text(content)
        if os.geteuid()==0:
            import grp
            self.deploy.restrict_release(self.prefix,release,grp.getgrnam('openplayx-'+self.role).gr_gid)

    def enable_lan(self):
        if self.role!='home':raise ConfigError('homeOnly','局域网直连选项仅用于 Home。')
        cfg=self.load()
        if not self.path.exists():return cfg # Fresh installs already use the LAN default.
        cfg['management']['listen']='0.0.0.0'
        self.validate_management(cfg['management'])
        return self.save(cfg,cfg['revision'])

    def recovery_info(self):
        if not self.path.exists():raise ConfigError('noConfig','没有待恢复文件。',409)
        backup=self.directory/(self.role+'.backup.json')
        if not backup.exists():raise ConfigError('noBackup','没有可用的配置备份。',409)
        cfg=read(backup);self.validate(cfg,self.secrets())
        return {'fileHash':hashlib.sha256(self.path.read_bytes()).hexdigest(),'backupRevision':cfg['revision']}

    def recover(self,expected_hash):
        with self.lock():
            info=self.recovery_info()
            if not isinstance(expected_hash,str) or expected_hash!=info['fileHash']:raise ConfigError('conflict','待恢复文件已变化，请重新检查。',409)
            cfg=read(self.directory/(self.role+'.backup.json'));revision=cfg['revision']
            original=self.path.read_bytes()
            try:
                current=json.loads(original)
                if isinstance(current,dict) and type(current.get('revision'))is int:revision=max(revision,current['revision'])
            except ValueError:pass
            preserved=self.directory/(self.role+'.damaged.'+str(time.time_ns())+'.json')
            with preserved.open('wb') as stream:stream.write(original);stream.flush();os.fsync(stream.fileno())
            preserved.chmod(0o600)
            clock_path=self.directory/'revision.json'
            clock=read(clock_path)['lastIssuedRevision'] if clock_path.exists() else revision
            if type(clock)is not int or clock<0:raise ConfigError('invalidRevision','修订元数据损坏。',409)
            cfg['revision']=max(revision,clock)+1;atomic(clock_path,{'lastIssuedRevision':cfg['revision']});atomic(self.path,cfg)
            statefile=self.directory/'status.json'
            if statefile.exists():
                try:
                    state=read(statefile)
                    if not isinstance(state,dict) or set(state)-{'appliedRevision','error','appliedAt','failedRevision'} or 'appliedRevision' not in state or (state['appliedRevision'] is not None and type(state['appliedRevision'])is not int) or state.get('error') not in [None,'applyFailed','stateRecovered','legacyRuntimeRolledBack']:raise ValueError()
                except (ConfigError,ValueError):
                    backup=self.directory/('status.damaged.'+str(time.time_ns())+'.json');shutil.copyfile(statefile,backup);backup.chmod(0o600)
                    atomic(statefile,{'appliedRevision':None,'error':'stateRecovered'})
            return cfg

    def restore(self,expected):
        backup=self.directory/(self.role+'.backup.json')
        if not backup.exists():raise ConfigError('noBackup','没有可恢复的配置。',409)
        cfg=read(backup);cfg['revision']=expected
        return self.save(cfg,expected)

    def _collect_secrets(self):
        references=set()
        for path in [self.path,self.directory/(self.role+'.backup.json'),self.directory/'last-good.json',self.prefix/'previous/logical.json']:
            if path.exists():
                cfg=read(path)
                references.update(v for owner in [cfg['proxy'],cfg['frp']] for k,v in owner.items() if k.endswith('CredentialRef') or k=='credentialRef')
        atomic(self.directory/'secrets.json',{k:v for k,v in self.secrets().items() if k in references})

    def import_legacy(self,filename,home_id=None):
        if self.path.exists():raise ConfigError('alreadyInitialized','已有配置，禁止覆盖初始化。',409)
        raw=read(filename);home_id=home_id or raw.get('homeId','home-main');cfg=self.blank();cfg['homeId']=identifier(home_id)
        p=raw['proxy'];cfg['proxy'].update(host=p['host'],port=p['port'],serverName=p['serverName'])
        cfg['frp']['controlPort']=raw.get('controlPort',7000)
        tlsdir=self.directory/'tls';tlsdir.mkdir(exist_ok=True,mode=0o700)
        def copy_tls(source,label):
            value=Path(source).read_bytes()
            if len(value)>131072:raise ConfigError('invalidCertificate','TLS 文件过大。')
            target=tlsdir/label;target.write_bytes(value);target.chmod(0o600);return 'tls/'+label
        if self.role=='relay':
            cfg['proxy'].update(listen=raw.get('listen','0.0.0.0'),certificateFile=copy_tls(p['certificatePath'],'proxy.crt'),keyFile=copy_tls(p['keyPath'],'proxy.key'))
            cfg['frp'].update(certificateFile=copy_tls(raw['frpCertificatePath'],'frps.crt'),keyFile=copy_tls(raw['frpKeyPath'],'frps.key'))
        else:
            cfg['proxy']['caCertificate']=p.get('caCertificate','');cfg['singBox']['socksPort']=raw.get('socksPort',1080)
            cfg['frp'].update(serverName=raw['frpServerName'],caFile=copy_tls(raw['frpCAPath'],'frps-ca.crt'))
        cfg['services']=[{'serviceId':s['id'],'relayPort':s['remotePort'],**({'targetHost':s['localHost'],'targetPort':s['localPort']} if self.role=='home' else {})} for s in raw['services']]
        if self.role=='home':atomic(self.directory/'grants.json',{'homeId':home_id,'relayHost':p['host'],'relayPort':p['port'],'services':[[s['serviceId'],s['relayPort']] for s in cfg['services']]})
        updates={'homeUUID':p['homeUUID'],'frpToken':raw['frpToken']}
        if self.role=='relay':updates['appUUID']=p['appUUID']
        return self.save(cfg,0,updates)
