#!/usr/bin/env python3
"""Freeze allocation-bearing result responses; never rewrite earlier fixtures."""
import copy, hashlib, json, pathlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
root=pathlib.Path(__file__).resolve().parents[1]/'testdata/process-epoch-vectors/v1'
key=Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
def c(x):return json.dumps(x,separators=(',',':')).encode()
def h(x):return hashlib.sha256(x).hexdigest()
def fixture(n):return json.loads((root/(n+'.json')).read_text())
def body(n):return json.loads(bytes.fromhex(fixture(n)['canonical_hex']))
def record(n):
 v=fixture(n)
 return {k:list(bytes.fromhex(v[f])) for k,f in [('body','canonical_hex'),('envelope','envelope_hex'),('signature','signature_hex')]}
def signed(x,request,nonce):
 b=c(x);e=json.loads(bytes.fromhex(fixture('BindReceipt')['envelope_hex']))
 e.update(domain='agentenv-process-epoch/node-response/v1',audience='controller/fixture',request_sha256=request,body_sha256=h(b),nonce=h(nonce.encode()))
 eb=c(e);return dict(body=list(b),envelope=list(eb),signature=list(key.sign(e['domain'].encode()+b'\0'+eb)))
positive=[]
def emit(name,kind,x,request=None):
 r=signed(x,request or h(c(x)),name);b=bytes(r['body']);e=bytes(r['envelope'])
 v=dict(name=name,kind=kind,canonical_hex=b.hex(),sha256=h(b),envelope_hex=e.hex(),signature_input_hex=(b'agentenv-process-epoch/node-response/v1\0'+e).hex(),public_key_hex=fixture('BindReceipt')['public_key_hex'],signature_hex=bytes(r['signature']).hex())
 (root/(name+'.json')).write_text(json.dumps(v,indent=2)+'\n');positive.append(name+'.json');return r
contexts=[]
for kind in ['Create','Restore']:
 for outcome in ['Running','Failed','Unknown']:
  old=body('Addendum2Dispatch'+kind+outcome);result={}
  for k,v in old.items():
   result[k]='agentenv-process-epoch-dispatch-result-v2' if k=='protocol' else v
   if k=='runtime_incarnation':result['host_allocation_id']='fixture-host-allocation'
  name='Addendum4Dispatch'+kind+outcome
  receipt=emit(name,'DispatchResultV2',result)
  lookup=body('Addendum3Dispatch'+kind+outcome+'Lookup');lookup.update(receipt_sha256=h(c(receipt)),receipt_kind='dispatch_result_v2')
  node=emit(name+'Lookup','LookupResponse',lookup,lookup['request_sha256'])
  response=dict(node=node,receipt=receipt);emit(name+'Response','ReceiptResponse',response,lookup['request_sha256'])
  contexts.append(dict(name=name+'Response.json',source=name+'.json',binding=lookup['binding'],request_sha256=lookup['request_sha256'],nonce=json.loads(bytes(node['envelope']))['nonce'],receipt_kind='dispatch_result_v2',state='dispatch_completed',accepted=True))
# Independently node-signed evidence with the right retirement/runtime/incarnation,
# but a different host allocation. Signature validity cannot repair the mismatch.
evidence=body('Addendum2HostCessation');evidence['host_allocation_id']='fixture-other-host-allocation'
receipt=emit('Addendum4ForeignAllocationEvidence','HostCessationEvidence',evidence)
lookup=body('Addendum3HostCessationLookup');lookup['receipt_sha256']=h(c(receipt))
node=emit('Addendum4ForeignAllocationLookup','LookupResponse',lookup,lookup['request_sha256'])
emit('Addendum4ForeignAllocationResponse','ReceiptResponse',dict(node=node,receipt=receipt),lookup['request_sha256'])
# These records are valid syntax/signatures and explicitly negative for the resolver.
context_negative=positive[-3:];positive=positive[:-3]
negative=[]
def bad(name,kind,x):negative.append(dict(name=name,kind=kind,canonical_hex=c(x).hex()))
x=body('Addendum4DispatchCreateRunning');del x['host_allocation_id'];bad('missing_allocation','DispatchResultV2',x)
x=body('Addendum4DispatchCreateRunning');x['host_allocation_id']='';bad('empty_allocation','DispatchResultV2',x)
x=body('Addendum4DispatchCreateRunning');x['protocol']='agentenv-process-epoch-v1';bad('v1_tag_cannot_supply_allocation','DispatchResultV2',x)
x=body('Addendum2DispatchCreateRunning');x['host_allocation_id']='fixture-host-allocation';bad('v1_remains_closed_to_new_fields','DispatchResult',x)
x=body('Addendum4DispatchCreateRunningLookup');x['state']='bound';bad('v2_is_not_bind','LookupResponse',x)
(root/'negative-addendum-4.json').write_text(json.dumps(negative,indent=2)+'\n')
(root/'addendum-4-manifest.json').write_text(json.dumps(dict(positive=positive,negative='negative-addendum-4.json',contexts=contexts,context_negative=context_negative,allocation_cases=[dict(dispatch_response='Addendum4Dispatch'+k+'RunningResponse.json',evidence_response=e,accepted=ok) for k in ['Create','Restore'] for e,ok in [('Addendum3HostCessationResponse.json',True),('Addendum4ForeignAllocationResponse.json',False)]]+[dict(dispatch_response='Addendum3DispatchCreateRunningResponse.json',evidence_response='Addendum3HostCessationResponse.json',accepted=False)],test_only_ed25519_seed_hex=bytes(range(32)).hex()),indent=2)+'\n')
