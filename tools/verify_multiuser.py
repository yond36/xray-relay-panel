"""Exercise multiple users against a NEW loopback-only test panel, without deploying nodes."""
import argparse
import base64
import http.cookiejar
import json
from pathlib import Path
import secrets
import urllib.error
import urllib.parse
import urllib.request

parser=argparse.ArgumentParser()
parser.add_argument('--url',default='http://127.0.0.1:8080')
parser.add_argument('--access',default='.local/multiuser-access.secret')
parser.add_argument('--output',default='.local/verification/multiuser-api.json')
args=parser.parse_args()
if urllib.parse.urlparse(args.url).hostname not in ['127.0.0.1','localhost','::1']:
    raise SystemExit('This integration fixture only accepts a loopback test panel')
class Client:
    def __init__(self):self.client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    def call(self,method,path,body=None):
        req=urllib.request.Request(args.url+path,data=json.dumps(body).encode() if body is not None else None,method=method,headers={'Origin':args.url,'Content-Type':'application/json'})
        try:
            with self.client.open(req,timeout=35) as response:
                data=response.read();return response.status,json.loads(data) if response.headers.get('Content-Type','').startswith('application/json') else data.decode()
        except urllib.error.HTTPError as error:
            data=error.read().decode();return error.code,json.loads(data) if data else {}
    def ok(self,method,path,body=None):
        code,data=self.call(method,path,body)
        assert code in [200,201,202],f'{method} {path}: HTTP {code}: {data}'
        return data

def denied(client,method,path,body=None):
    code,data=client.call(method,path,body)
    assert code in [403,404],f'Unauthorized operation allowed: {method} {path}: HTTP {code}'

admin,a,b=Client(),Client(),Client()
bootstrap=admin.ok('GET','/api/bootstrap')
assert not bootstrap['initialized'],'Use a fresh test data directory; existing panels are never modified by this fixture'
access={key:{'username':name,'password':secrets.token_urlsafe(24)} for key,name in [('admin','qa_admin'),('a','qa_user_a'),('b','qa_user_b')]}
access_path=Path(args.access);access_path.parent.mkdir(parents=True,exist_ok=True);access_path.write_text(json.dumps(access,indent=2),encoding='utf-8')
admin.ok('POST','/api/auth/setup',access['admin'])
initial=admin.ok('GET','/api/state');admin_id=initial['current_user']['id']
assert initial['current_user']['role']=='admin'
assert not admin.ok('GET','/api/bootstrap')['registration_open']
denied(a,'POST','/api/auth/register',access['a'])
settings=admin.ok('GET','/api/settings');settings['registration_open']=True
admin.ok('PUT','/api/settings',settings)
assert a.ok('GET','/api/bootstrap')['registration_open']
a.ok('POST','/api/auth/register',access['a']);b.ok('POST','/api/auth/register',access['b'])
a_id=a.ok('GET','/api/state')['current_user']['id'];b_id=b.ok('GET','/api/state')['current_user']['id']
assert a_id!=b_id and a_id!=admin_id
assert a.ok('GET','/api/state')['current_user']['role']=='user'
code,payload=Client().call('POST','/api/auth/register',dict(access['a'],username='qa_role_injection',role='admin'))
assert code in [400,403] or code in [200,201] and payload.get('user',{}).get('role')=='user','Registration escalated role'
code,_=Client().call('POST','/api/auth/register',dict(access['a'],username='QA_USER_A'))
assert code in [400,409],'Case-insensitive username uniqueness was not enforced'
denied(a,'GET','/api/users');denied(a,'PUT','/api/settings',dict(settings,registration_open=False))
denied(a,'POST','/api/users',dict(access['a'],username='qa_unauthorized',role='admin'))
denied(a,'POST','/api/nodes',{'name':'forbidden local','kind':'local','public_host':'local.example.invalid'})
settings['registration_open']=False;admin.ok('PUT','/api/settings',settings)
denied(Client(),'POST','/api/auth/register',{'username':'qa_closed','password':secrets.token_urlsafe(24)})
existing=Client();existing.ok('POST','/api/auth/login',access['a'])
managed=admin.ok('POST','/api/users',{'username':'qa_managed','password':secrets.token_urlsafe(24),'role':'user'})
assert managed['role']=='user'

fingerprint='SHA256:'+base64.b64encode(b'qa-fingerprint-for-no-connection!!'[:32]).decode().rstrip('=')
def create(client,label,owner,local=False):
    node=client.ok('POST','/api/nodes',{'name':'QA node '+label,'kind':'local' if local else 'ssh','host':label+'.example.invalid','ssh_port':22,'username':'root','auth_mode':'password','password':'not-a-real-server-credential','fingerprint':fingerprint,'public_host':label+'.example.invalid','core_version':'1.8.24' if label=='a' else 'v26.10.31'})
    assert node['owner_id']==owner
    if label=='a':assert node['core_version']=='v1.8.24'
    upstream=client.ok('POST','/api/upstreams',{'name':'QA upstream '+label,'protocol':'socks','server':'proxy-'+label+'.example.invalid','port':1080,'outbound':{'protocol':'socks','settings':{'servers':[{'address':'proxy-'+label+'.example.invalid','port':1080}]}}})
    relay=client.ok('POST','/api/relays',{'name':'QA relay '+label,'node_id':node['id'],'upstream_id':upstream['id'],'protocol':'vless','network':'tcp','security':'reality','enabled':True,'listen':'0.0.0.0','public_host':label+'.example.invalid','port':30443,'server_name':'www.cloudflare.com','target':'www.cloudflare.com:443'})
    assert upstream['owner_id']==owner and relay['owner_id']==owner
    return node,upstream,relay
na,ua,ra=create(a,'a',a_id);nb,ub,rb=create(b,'b',b_id);nc,uc,rc=create(admin,'admin',admin_id,True)
sa=a.ok('GET','/api/state');sb=b.ok('GET','/api/state');all_state=admin.ok('GET','/api/state')
for state,owner in [(sa,a_id),(sb,b_id)]:
    for field in ['nodes','upstreams','relays','jobs','probes','subscriptions']:
        assert all(row.get('owner_id')==owner for row in state[field]),'Cross-user data in '+field
assert len(all_state['nodes'])==3 and len(all_state['upstreams'])==3 and len(all_state['relays'])==3,'Administrator cannot see all configurations'
assert {entry['username'] for entry in admin.ok('GET','/api/users')} >= {x['username'] for x in access.values()}
for method,path,body in [('GET','/api/upstreams/'+ub['id'],None),('PUT','/api/upstreams/'+ub['id'],{'name':'changed'}),('DELETE','/api/upstreams/'+ub['id'],None),('GET','/api/relays/'+rb['id']+'/share',None),('PUT','/api/relays/'+rb['id'],rb),('DELETE','/api/relays/'+rb['id'],None),('PUT','/api/nodes/'+nb['id'],nb),('DELETE','/api/nodes/'+nb['id'],None),('GET','/api/nodes/'+nb['id']+'/logs',None),('POST','/api/nodes/'+nb['id']+'/apply',{}),('POST','/api/nodes/'+nb['id']+'/probe',{'upstream_id':ub['id']}),('POST','/api/nodes/'+nb['id']+'/service',{'action':'stop'}),('POST','/api/nodes/test',nb)]:
    denied(a,method,path,body)
code,_=a.call('POST','/api/relays',dict(ra,id='',name='cross owner',upstream_id=ub['id']))
assert code in [400,403,404,409],'Cross-owner relay references accepted'
code,response=a.call('PUT','/api/upstreams/'+ua['id'],dict(ua,owner_id=b_id))
assert code in [400,403,404,409] or code==200 and response.get('owner_id')==a_id,'Owner transfer accepted'
assert a.ok('GET','/api/upstreams/'+ua['id'])['owner_id']==a_id,'Persisted owner changed'
admin.ok('PUT','/api/upstreams/'+ub['id'],{'name':'QA upstream b edited by admin'})
assert b.ok('GET','/api/upstreams/'+ub['id'])['owner_id']==b_id

def feed(client,expected,forbidden):
    token=client.ok('GET','/api/settings')['subscription_token']
    data=Client().ok('GET','/sub/'+token)
    text=base64.b64decode(data).decode()
    assert expected['uuid'] in text and all(item['uuid'] not in text for item in forbidden),'Personal subscription leaked another account'
    return token
admin_token=feed(admin,rc,[ra,rb]);a_token=feed(a,ra,[rb,rc]);b_token=feed(b,rb,[ra,rc])
assert len({admin_token,a_token,b_token})==3
rotated=a.ok('POST','/api/settings/rotate-token',{})
assert a.ok('GET','/api/settings')['subscription_token']!=a_token
code,_=Client().call('GET','/sub/'+a_token);assert code==404,'Old personal token still works'
assert b.ok('GET','/api/settings')['subscription_token']==b_token
code,releases=a.call('GET','/api/core/releases')
assert code==200 and releases.get('releases') or code==502 and releases.get('error'),'Official version endpoint did not provide a list or an explicit recoverable error'
report={'status':'passed','registration_default_closed':True,'admin_registration_toggle':True,'registration_username_password_only':True,'normal_role_enforced':True,'admin_user_creation_while_closed':True,'existing_login_works_while_closed':True,'user_configuration_isolation':True,'cross_user_id_operations_denied':13,'cross_owner_references_denied':True,'ownership_immutable':True,'admin_all_configurations':True,'all_personal_feeds_owner_only':True,'personal_token_rotation_isolated':True,'custom_core_version_normalized':True,'official_list_available':code==200,'official_release_count':len(releases.get('releases',[])),'first_official_tag':releases['releases'][0]['tag'] if releases.get('releases') else None,'official_release_error':releases.get('error')}
output=Path(args.output);output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(report,ensure_ascii=False,indent=2))
