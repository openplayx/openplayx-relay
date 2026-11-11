import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
class PairingTest(unittest.TestCase):
 def test_role_credentials_and_no_overwrite(self):
  with tempfile.TemporaryDirectory() as folder:
   p=Path(folder)
   subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=relay.test','-keyout',str(p/'key.pem'),'-out',str(p/'cert.pem')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   args=['python3',str(ROOT/'scripts/pair.py'),'--host','relay.test','--tls-name','relay.test','--certificate',str(p/'cert.pem'),'--key',str(p/'key.pem'),'--output',str(p/'paired')]
   subprocess.run(args,check=True,stdout=subprocess.DEVNULL)
   cfg=json.loads((p/'paired/relay/relay.json').read_text());home=json.loads((p/'paired/home/home.json').read_text());app=json.loads((p/'paired/app-jellyfin.json').read_text())
   relay_secrets=json.loads((p/'paired/relay/secrets.json').read_text());home_secrets=json.loads((p/'paired/home/secrets.json').read_text())
   self.assertEqual(relay_secrets[cfg['proxy']['appCredentialRef']],app['outbound']['uuid'])
   self.assertEqual(relay_secrets[cfg['proxy']['homeCredentialRef']],home_secrets[home['proxy']['homeCredentialRef']])
   self.assertEqual(cfg['homeId'],home['homeId']);self.assertEqual(cfg['homeId'],app['homeId'])
   self.assertNotIn('appCredentialRef',home['proxy']);self.assertNotIn(app['outbound']['uuid'],home_secrets.values());self.assertNotIn('frpToken',app)
   self.assertFalse((p/'paired/deployment.json').exists());self.assertFalse((p/'paired/frps.key').exists())
   self.assertNotEqual(subprocess.run(args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode,0)
if __name__=='__main__':unittest.main()
