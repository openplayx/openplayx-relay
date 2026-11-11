import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('deploy',ROOT/'scripts/manage.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class DeploymentTest(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.output=Path(self.temp.name)
  self.cfg=json.loads((ROOT/'config/deployment.example.json').read_text())
 def test_boundaries(self):
  m.render(self.cfg,self.output)
  sing=json.loads((self.output/'sing-box.json').read_text())
  frp=(self.output/(m.FRP+'.toml')).read_text()
  if m.ROLE=='relay':
   self.assertIn('bindAddr = "127.0.0.1"',frp)
   self.assertIn('proxyBindAddr = "127.0.0.1"',frp)
   self.assertEqual(sing['route']['rules'][-1]['action'],'reject')
   self.assertEqual(sing['route']['rules'][0]['auth_user'],['home'])
   self.assertEqual(sing['route']['rules'][1]['auth_user'],['app'])
  else:
   self.assertIn('transport.proxyURL = "socks5://127.0.0.1:1080"',frp)
   self.assertIn('transport.tls.trustedCaFile',frp)
   self.assertEqual([o['type'] for o in sing['outbounds']],['vless'])
  self.assertEqual((self.output/'sing-box.json').stat().st_mode&0o777,0o600)
 def test_mapping_collision_and_weak_credentials_rejected(self):
  self.cfg['services'].append(self.cfg['services'][0].copy())
  with self.assertRaises(ValueError):m.render(self.cfg,self.output)
  self.cfg['services'].pop();self.cfg['frpToken']='weak'
  with self.assertRaises(ValueError):m.render(self.cfg,self.output)
 def test_credentials_preserved_on_repeated_render(self):
  m.render(self.cfg,self.output);first=(self.output/'sing-box.json').read_bytes()
  m.render(self.cfg,self.output);self.assertEqual(first,(self.output/'sing-box.json').read_bytes())
 def test_service_group_can_traverse_binaries_but_secrets_are_not_world_readable(self):
  prefix=self.output/'install';release=prefix/'releases/1'
  (release/'bin').mkdir(parents=True);(release/'config/tls').mkdir(parents=True)
  (release/'bin/sing-box').write_text('binary')
  (release/'config/tls/key.pem').write_text('test-only-secret')
  with patch.object(m.os,'chown'):
   m.restrict_release(prefix,release,123)
  self.assertEqual((release/'bin').stat().st_mode&0o777,0o750)
  self.assertEqual((release/'bin/sing-box').stat().st_mode&0o777,0o750)
  self.assertEqual((release/'config/tls/key.pem').stat().st_mode&0o777,0o640)
 def test_locked_archives_have_complete_sha256(self):
  locks=json.loads((ROOT/'versions.lock.json').read_text())
  for component in ['sing-box',m.FRP]:
   for arch in ['linux-amd64','linux-arm64','darwin-amd64','darwin-arm64']:
    self.assertRegex(locks[component][arch]['sha256'],r'^[0-9a-f]{64}$')
if __name__=='__main__':unittest.main()
