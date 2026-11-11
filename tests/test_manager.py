import copy
import http.client
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'manager'))
from configuration import Configuration,ConfigError,atomic,read
import server

class ManagerTest(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.folder=Path(self.temp.name);self.store=Configuration(self.folder/'state',server.ROLE,repository=ROOT,binaries=self.folder/'bin',prefix=self.folder/'runtime',controller=lambda action,cfg:None)
  tls=self.store.directory/'tls';tls.mkdir()
  for name in ['proxy.crt','proxy.key','frps.crt','frps.key','ca.crt']:(tls/name).write_text('test fixture only')
  self.cfg=self.store.blank();self.cfg['services']=[{'serviceId':'jellyfin','relayPort':18096,**({'targetHost':'192.168.50.10','targetPort':8096} if server.ROLE=='home' else {})}]
  if server.ROLE=='relay':self.cfg['proxy'].update(certificateFile='tls/proxy.crt',keyFile='tls/proxy.key');self.cfg['frp'].update(certificateFile='tls/frps.crt',keyFile='tls/frps.key')
  else:
   self.cfg['frp']['caFile']='tls/ca.crt'
   atomic(self.store.directory/'grants.json',{'homeId':'home-main','relayHost':'relay.example.com','relayPort':443,'services':[['jellyfin',18096]]})
  self.updates={'homeUUID':'11111111-1111-4111-8111-111111111111','frpToken':'test-token-'*6}
  if server.ROLE=='relay':self.updates['appUUID']='22222222-2222-4222-8222-222222222222'
  self.saved=self.store.save(self.cfg,0,self.updates)
 def test_secrets_revision_and_backup(self):
  data=self.store.path.read_text()
  for value in self.updates.values():self.assertNotIn(value,data)
  self.assertEqual((self.store.directory/'secrets.json').stat().st_mode&0o777,0o600)
  with self.assertRaises(ConfigError) as e:self.store.save(self.cfg,0,self.updates)
  self.assertEqual(e.exception.status,409)
  nextcfg=copy.deepcopy(self.saved);nextcfg['log']['level']='error'
  self.store.save(nextcfg,1)
  restored=self.store.restore(2)
  self.assertEqual(restored['revision'],3);self.assertEqual(restored['log']['level'],'warn')
 def test_corrupt_or_future_file_never_overwritten(self):
  self.store.path.write_text('{broken')
  with self.assertRaises(ConfigError):self.store.save(self.saved,1)
  self.assertEqual(self.store.path.read_text(),'{broken')
  atomic(self.store.path,{'schemaVersion':99,'revision':50})
  with self.assertRaises(ConfigError):self.store.load()
  self.assertEqual(read(self.store.path)['schemaVersion'],99)
 def test_explicit_recovery_preserves_corrupt_file_and_uses_hash_conflict_check(self):
  self.store.save(copy.deepcopy(self.saved),1)
  self.store.path.write_text('{damaged')
  info=self.store.recovery_info()
  with self.assertRaises(ConfigError):self.store.recover('wrong-hash')
  restored=self.store.recover(info['fileHash'])
  self.assertEqual(restored['revision'],3)
  copies=list(self.store.directory.glob(server.ROLE+'.damaged.*.json'))
  self.assertEqual(copies[0].read_text(),'{damaged')
  self.assertEqual(self.store.load()['revision'],3)
 def test_tls_import_is_bounded_private_and_not_a_path_write_api(self):
  certificate=self.folder/'fixture.crt';key=self.folder/'fixture.key'
  import subprocess
  subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-keyout',str(key),'-out',str(certificate)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  ref=self.store.import_tls('certificate',certificate.read_text())
  private=self.store.import_tls('privateKey',key.read_text())
  self.assertEqual((self.store.directory/private).stat().st_mode&0o777,0o600)
  self.assertTrue(ref.startswith('tls/'));self.assertTrue(private.startswith('tls/'))
  with self.assertRaises(ConfigError):self.store.import_tls('../../outside',key.read_text())
  with self.assertRaises(ConfigError):self.store.import_tls('certificate',key.read_text())
  self.assertNotIn(key.read_text(),self.store.path.read_text())
 def test_backend_rejects_paths_ports_unknown_fields_and_unauthorized_mapping(self):
  for change in ['port','path','field','mapping']:
   cfg=copy.deepcopy(self.saved)
   if change=='port':cfg['services'][0]['relayPort']=cfg['frp']['controlPort']
   elif change=='path':cfg['frp']['caFile' if server.ROLE=='home' else 'keyFile']='../../arbitrary'
   elif change=='field':cfg['shellCommand']='whoami'
   elif server.ROLE=='home':cfg['services'][0]['relayPort']=19000
   else:cfg['proxy']['appCredentialRef']=cfg['proxy']['homeCredentialRef']
   with self.subTest(change=change),self.assertRaises(ConfigError):self.store.save(cfg,1)
  self.assertEqual(self.store.load()['revision'],1)
 def _fake_binaries(self):
  self.store.binaries.mkdir()
  for name in ['sing-box','frps' if server.ROLE=='relay' else 'frpc']:
   path=self.store.binaries/name;path.write_text('#!/bin/sh\nexit 0\n');path.chmod(0o755)
 def test_save_is_not_apply_and_failed_apply_restores_runtime(self):
  self._fake_binaries();self.assertIsNone(self.store.status()['appliedRevision'])
  self.store.apply(1);old=(self.store.prefix/'current').resolve()
  cfg=copy.deepcopy(self.saved);cfg['log']['level']='error';self.store.save(cfg,1)
  def failed(action,cfg):
   if cfg['revision']==2:raise OSError('test-only component failure')
  self.store.controller=failed
  with self.assertRaises(ConfigError):self.store.apply(2)
  self.assertEqual((self.store.prefix/'current').resolve(),old)
  self.assertEqual(self.store.status()['appliedRevision'],1)
  self.assertEqual(self.store.load()['revision'],2)
  self.assertEqual(self.store.status()['error'],'applyFailed')
 def test_cli_install_and_rollback_report_the_same_json_revision(self):
  deploy=self.store.deploy
  counter=[0]
  def install_fixture(cfg,prefix):
   counter[0]+=1;release=prefix/'releases'/str(counter[0]);release.mkdir(parents=True)
   current=prefix/'current'
   if current.exists():
    previous=prefix/'previous';previous.unlink(missing_ok=True);previous.symlink_to(current.resolve());current.unlink()
   current.symlink_to(release)
  with patch.object(deploy,'install',side_effect=install_fixture),patch.object(deploy,'systemctl'):
   deploy.install_from_file(self.store.path,self.store.prefix)
   self.assertEqual(self.store.status()['appliedRevision'],1)
   cfg=copy.deepcopy(self.saved);cfg['log']['level']='error';self.store.save(cfg,1)
   deploy.install_from_file(self.store.path,self.store.prefix)
   self.assertEqual(self.store.status()['appliedRevision'],2)
   deploy.rollback_runtime(self.store.prefix,self.store.path)
   self.assertEqual(self.store.status()['appliedRevision'],1)
   self.assertEqual(self.store.status()['desiredRevision'],2)
 def test_cli_install_failure_reports_saved_but_not_effective_like_web(self):
  deploy=self.store.deploy
  with patch.object(deploy,'install',side_effect=ValueError('boom')):
   with self.assertRaises(ValueError):deploy.install_from_file(self.store.path,self.store.prefix)
  state=self.store.status()
  self.assertEqual((state['appliedRevision'],state['error'],state['failedRevision'],state['savedIsApplied']),(None,'applyFailed',1,False))
 def test_previous_runtime_secrets_survive_multiple_pending_rotations(self):
  self._fake_binaries();self.store.apply(1)
  old_ref=self.saved['frp']['credentialRef']
  second=self.store.save(copy.deepcopy(self.saved),1,{'frpToken':'replacement-token-B-'*4})
  self.store.save(second,2,{'frpToken':'replacement-token-C-'*4})
  self.store.apply(3)
  self.assertIn(old_ref,self.store.secrets())
  self.assertEqual(read(self.store.prefix/'previous/logical.json')['revision'],1)
 def test_http_auth_csrf_origins_expiration_and_redaction(self):
  app=server.Server(self.store,self.saved['management'],address=('127.0.0.1',0))
  thread=threading.Thread(target=app.serve_forever,daemon=True);thread.start()
  self.addCleanup(app.server_close);self.addCleanup(app.shutdown)
  origin='http://127.0.0.1:'+str(app.server_address[1])
  def request(path,body=None,cookie=None,csrf=None,request_origin=origin):
   conn=http.client.HTTPConnection('127.0.0.1',app.server_address[1],timeout=5)
   headers={'Host':'127.0.0.1:'+str(app.server_address[1]),'Origin':request_origin}
   if cookie:headers['Cookie']=cookie
   if csrf:headers['X-CSRF-Token']=csrf
   if body is not None:headers['Content-Type']='application/json'
   conn.request('POST' if body is not None else 'GET',path,None if body is None else json.dumps(body),headers)
   response=conn.getresponse();data=json.loads(response.read());status=response.status;cookievalue=response.getheader('Set-Cookie');conn.close();return status,data,cookievalue
  self.assertEqual(request('/api/config')[0],401)
  token=(self.store.directory/'bootstrap-token').read_text().strip()
  status,data,cookie=request('/api/login',{'password':token});self.assertEqual(status,200)
  self.assertIn('HttpOnly',cookie);self.assertIn('SameSite=Strict',cookie)
  cookie=cookie.split(';')[0];csrf=data['csrfToken']
  status,data,_=request('/api/config',cookie=cookie);self.assertEqual(status,200)
  for value in self.updates.values():self.assertNotIn(value,json.dumps(data))
  self.assertEqual(request('/api/save',{'config':self.saved,'expectedRevision':1},cookie=cookie)[0],403)
  self.assertEqual(request('/api/save',{'config':self.saved,'expectedRevision':1},cookie=cookie,csrf=csrf,request_origin='https://evil.example')[0],403)
  self.assertEqual(request('/api/save',{'config':self.saved,'expectedRevision':1},cookie=cookie,csrf=csrf)[0],200)
  self.assertEqual(request('/api/save',{'config':self.saved,'expectedRevision':1},cookie=cookie,csrf=csrf)[0],409)
  status,data,_=request('/api/password',{'password':'new-test-password-with-32-characters'},cookie=cookie,csrf=csrf);self.assertEqual(status,200)
  self.assertEqual(request('/api/config',cookie=cookie)[0],401)
  self.assertEqual(request('/api/login',{'password':token})[0],401)
  status,data,newcookie=request('/api/login',{'password':'new-test-password-with-32-characters'});self.assertEqual(status,200)
  app.admin.now=lambda:time.time()+3600
  self.assertEqual(request('/api/config',cookie=newcookie.split(';')[0])[0],401)
 def test_bootstrap_expiry(self):
  now=[1000];admin=server.Admin(self.store.directory,now=lambda:now[0]);admin.bootstrap()
  token=(self.store.directory/'bootstrap-token').read_text().strip();now[0]=2000
  with self.assertRaises(ConfigError):admin.authenticate(token,'local')

if __name__=='__main__':unittest.main()
