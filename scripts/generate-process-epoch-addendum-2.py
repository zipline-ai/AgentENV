#!/usr/bin/env python3
"""Reproduce addendum-2 only; keys and host evidence below are wire fixtures."""
import copy, hashlib, json, pathlib, uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
root=pathlib.Path(__file__).resolve().parents[1]/'testdata/process-epoch-vectors/v1'
s=json.loads((root/'schema.json').read_text()); seed=bytes(range(32));key=Ed25519PrivateKey.from_private_bytes(seed)
pub=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
def c(x):return json.dumps(x,separators=(',',':')).encode()
def h(x):return hashlib.sha256(x).hexdigest()
def uid(x):return str(uuid.uuid5(uuid.NAMESPACE_URL,'https://example.invalid/epoch-addendum-2/'+x))
def fixture(n):return json.loads(bytes.fromhex(json.loads((root/(n+'.json')).read_text())['canonical_hex']))
def order(k,x):return {f['name']:order(f['type'].rstrip('?'),x[f['name']]) if f['type'].rstrip('?') in s['types'] else x[f['name']] for f in s['types'][k] if f['name'] in x}
env=json.loads(bytes.fromhex(json.loads((root/'BindReceipt.json').read_text())['envelope_hex'])); binding=fixture('InitialBindRequest')['binding'];positive=[]
def emit(name,kind,x,domain='agentenv-process-epoch/node-response/v1',signing_key=key):
 b=c(order(kind,x));e=copy.deepcopy(env);e.update(domain=domain,audience='agentenv-process-epoch/retire/v1' if kind=='RetirementAuthority' else 'controller/fixture',request_sha256=h(b),body_sha256=h(b),nonce=h(name.encode()));eb=c(e);inp=domain.encode()+b'\0'+eb
 v=dict(name=name,kind=kind,canonical_hex=b.hex(),sha256=h(b),envelope_hex=eb.hex(),signature_input_hex=inp.hex(),public_key_hex=pub,signature_hex=signing_key.sign(inp).hex());(root/(name+'.json')).write_text(json.dumps(v,indent=2)+'\n');positive.append(name+'.json');return v
result=dict(protocol='agentenv-process-epoch-v1',dispatch_kind='restore',operation_id=uid('dispatch'),dispatch_request_sha256=h(b'originating-dispatch-request'),node_id=binding['node_id'],node_incarnation=binding['node_incarnation'],runtime_id=binding['runtime_id'],runtime_incarnation=binding['runtime_incarnation'],guest_boot_id=binding['guest_boot_id'],process_endpoint='https://fixture.invalid:443',guest_build_sha256=h(b'build'),enrollment_revision=binding['enrollment_revision'],node_ledger_revision=12,outcome='running',node_observed_at=1700000000000)
for kind in ['create','restore']:
 for outcome in ['running','failed','unknown']:
  x=copy.deepcopy(result);x.update(dispatch_kind=kind,outcome=outcome);emit('Addendum2Dispatch'+kind.title()+outcome.title(),'DispatchResult',x)
authority=dict(protocol='agentenv-process-epoch-v1',operation_id=uid('retirement'),tenant_id=binding['tenant_id'],sandbox_family=binding['sandbox_family'],sandbox_id=binding['sandbox_id'],transition_id=binding['transition_id'],runtime_id=binding['runtime_id'],runtime_incarnation=binding['runtime_incarnation'],enrollment_revision=binding['enrollment_revision'],expected_session_id=binding['reserved_session_id'],reason='epoch_seal_retire',issued_at=1700000000000,expires_at=1700000030000)
a=emit('Addendum2Retirement','RetirementAuthority',authority,'agentenv-process-epoch/retire/v1')
x=copy.deepcopy(authority);x['affected_seal_receipt']=dict(operation_id=uid('seal'),envelope_sha256=h(b'prior-seal-envelope-digest'));emit('Addendum2RetirementAffectedSeal','RetirementAuthority',x,'agentenv-process-epoch/retire/v1')
evidence=dict(retirement_operation_id=authority['operation_id'],retirement_request_sha256=a['sha256'],runtime_id=binding['runtime_id'],runtime_incarnation=binding['runtime_incarnation'],host_allocation_id='fixture-host-allocation',cessation_method='fixture-only-not-execution-evidence',host_observed_at=1700000001000,no_second_copy=True,node_ledger_revision=13)
emit('Addendum2HostCessation','HostCessationEvidence',evidence)
negative=[]
def bad(n,k,x):negative.append(dict(name=n,kind=k,canonical_hex=c(x).hex()))
x=order('HostCessationEvidence',evidence);x.pop('no_second_copy');bad('missing_no_second_copy','HostCessationEvidence',x)
x=order('HostCessationEvidence',evidence);x['no_second_copy']=False;bad('second_copy_not_excluded','HostCessationEvidence',x)
for k,x in [('DispatchResult',result),('RetirementAuthority',authority),('HostCessationEvidence',evidence)]:
 x=order(k,x);x['request_sha256']=h(b'self');bad('body_digest_forbidden_'+k,k,x)
x=order('RetirementAuthority',authority);x.pop('operation_id');bad('missing_signed_operation_id','RetirementAuthority',x)
x=order('DispatchResult',result);x.pop('dispatch_request_sha256');bad('missing_originating_request','DispatchResult',x)
(root/'negative-addendum-2.json').write_text(json.dumps(negative,indent=2)+'\n')
# Cryptographically valid but contextually foreign, and guest-key impostor.
x=copy.deepcopy(evidence);x['runtime_incarnation']=uid('foreign');foreign=emit('Addendum2WrongIncarnation','HostCessationEvidence',x);positive.pop()
guest=emit('Addendum2GuestImpostor','HostCessationEvidence',evidence,signing_key=Ed25519PrivateKey.from_private_bytes(bytes(range(32,64))));positive.pop()
(root/'addendum-2-manifest.json').write_text(json.dumps(dict(positive=positive,negative='negative-addendum-2.json',context_negative=['Addendum2WrongIncarnation.json','Addendum2GuestImpostor.json'],test_only_ed25519_seed_hex=seed.hex()),indent=2)+'\n')
