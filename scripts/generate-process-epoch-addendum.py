#!/usr/bin/env python3
"""Reproduce only the v1 addendum fixtures; never rewrite original vectors."""
import copy, hashlib, json, pathlib, uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
root=pathlib.Path(__file__).resolve().parents[1]/'testdata/process-epoch-vectors/v1'
s=json.loads((root/'schema.json').read_text()); seed=bytes(range(32)); key=Ed25519PrivateKey.from_private_bytes(seed)
pub=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
def c(x):return json.dumps(x,separators=(',',':'),ensure_ascii=False).encode()
def h(x):return hashlib.sha256(x).hexdigest()
def uid(x):return str(uuid.uuid5(uuid.NAMESPACE_URL,'https://example.invalid/epoch-addendum/'+x))
def body(n):return json.loads(bytes.fromhex(json.loads((root/(n+'.json')).read_text())['canonical_hex']))
def order(kind,x):
 return {f['name']:order(f['type'].rstrip('?'),x[f['name']]) if f['type'].rstrip('?') in s['types'] else x[f['name']] for f in s['types'][kind] if f['name'] in x}
env=json.loads(bytes.fromhex(json.loads((root/'BindReceipt.json').read_text())['envelope_hex']))
positive=[]; containers=[]
def signed(kind,x,request_hash,nonce):
 b=c(order(kind,x));e=copy.deepcopy(env);e.update(domain='agentenv-process-epoch/node-response/v1',signer=x.get('binding',x.get('request',{}).get('binding',{})).get('node_id','fixture-node_id'),audience='controller/fixture',request_sha256=request_hash,nonce=h(nonce.encode()),body_sha256=h(b));eb=c(e)
 return {'body':list(b),'envelope':list(eb),'signature':list(key.sign(e['domain'].encode()+b'\0'+eb))}
def emit(name,kind,x,request_hash):
 r=signed(kind,x,request_hash,name);b=bytes(r['body']);eb=bytes(r['envelope']);e=json.loads(eb)
 v=dict(name=name,kind=kind,canonical_hex=b.hex(),sha256=h(b),envelope_hex=eb.hex(),signature_input_hex=(e['domain'].encode()+b'\0'+eb).hex(),public_key_hex=pub,signature_hex=bytes(r['signature']).hex())
 (root/(name+'.json')).write_text(json.dumps(v,indent=2)+'\n');positive.append(name+'.json');return r
initial=body('InitialBindRequest'); transition=body('TransitionBindRestore')
receipts={}
for label,req in [('Initial',initial),('Restore',transition)]:
 b=copy.deepcopy(req['binding']);r=dict(binding=b,request_sha256=h(c(req)),receipt_id=uid('bind-'+label),kind='initial' if label=='Initial' else 'transition',state='bound_closed',node_ledger_revision=9,guest_journal_revision=0,evidence=dict(evidence_class='host_dispatch_recorded',evidence_id=uid('bind-evidence-'+label),evidence_sha256=h(label.encode())))
 if label=='Initial':r['adoption_sha256']=req['adoption_sha256']
 else:r.update(expected_session_id=req['expected_session_id'],seal_receipt_id=req['seal_receipt_id'],seal_receipt_sha256=req['seal_receipt_sha256'])
 receipts[label]=emit('AddendumBindReceipt'+label,'BindReceipt',r,r['request_sha256'])
pending_bind=json.loads(bytes(receipts['Initial']['body']));pending_bind['state']='incomplete';pending_bind['receipt_id']=uid('bind-incomplete');pending_bind_record=emit('AddendumBindReceiptIncomplete','BindReceipt',pending_bind,pending_bind['request_sha256'])
release=body('ReleaseRequest');release['binding']=copy.deepcopy(initial['binding']);release['binding']['operation_id']=uid('release');release.update(bind_receipt_id=uid('bind-Initial'),bind_receipt_sha256=h(c(receipts['Initial'])),installed_session_id=initial['binding']['reserved_session_id'])
# Exact request bytes are included in every release observation, preserving deadline/revision.
release_hash=h(c(order('ReleaseRequest',release)))
release_records={}
for outcome in ['accepted','incomplete','released']:
 r=dict(request=release,request_sha256=release_hash,receipt_id=uid('release-'+outcome),outcome=outcome,node_ledger_revision=10,obligations_retained=True)
 release_records[outcome]=emit('AddendumReleaseReceipt'+outcome.title(),'ReleaseReceipt',r,release_hash)
seal=body('SealReceipt');seal['request']['retirement_authority_id']=uid('retirement');seal['request']['retirement_authority_sha256']=h(b'pending-authority-definition-wire-fixture-only');seal['request_sha256']=h(c(order('SealRequest',seal['request'])));seal.update(state='sealed',execution_outcome='scope_retired');seal['evidence']['evidence_class']='host_scope_stopped';seal_record=emit('AddendumSealReceiptSyntaxOnly','SealReceipt',seal,seal['request_sha256'])
for state in ['claimed','closing','completed_seal','bind_pending','bound','release_pending','released','unknown']:
 original=seal['request'];rh=seal['request_sha256'];record=None;kind=None
 if state in ['bind_pending','bound']:original=initial;rh=h(c(initial))
 if state in ['release_pending','released']:original=release;rh=release_hash
 if state=='completed_seal':record=seal_record;kind='seal'
 if state=='bound':record=receipts['Initial'];kind='bind'
 if state=='bind_pending':record=pending_bind_record;kind='bind'
 if state=='release_pending':record=release_records['accepted'];kind='release'
 if state=='released':record=release_records['released'];kind='release'
 result=dict(binding=original['binding'],request_sha256=rh,state=state,node_ledger_revision=10)
 if record:
  rb=json.loads(bytes(record['body']));result.update(receipt_id=rb['receipt_id'],receipt_sha256=h(c(record)),receipt_kind=kind)
 if state in ['closing','completed_seal']:result['affected_operations_sha256']=seal['affected_operations_sha256']
 node=emit('AddendumLookup'+state.title().replace('_',''),'LookupResponse',result,rh)
 container={'node':node}
 if record:container['receipt']=record
 emit('AddendumResponse'+state.title().replace('_',''),'ReceiptResponse',container,rh)
 containers.append('AddendumResponse'+state.title().replace('_','')+'.json')
negative=[]
def bad(name,kind,x):negative.append(dict(name=name,kind=kind,canonical_hex=c(order(kind,x)).hex()))
r=json.loads(bytes(release_records['released']['body']));r['obligations_retained']=False;bad('release_cannot_settle_obligations','ReleaseReceipt',r)
r=json.loads(bytes(release_records['released']['body']));r['outcome']='stopped';bad('release_unknown_outcome','ReleaseReceipt',r)
r=json.loads(bytes(release_records['released']['body']));r['request']['lease_not_after_unix_ms']=0;bad('release_zero_deadline','ReleaseReceipt',r)
r=json.loads(bytes(receipts['Restore']['body']));r.pop('seal_receipt_id');bad('transition_bind_missing_seal_id','BindReceipt',r)
r=json.loads(bytes(receipts['Initial']['body']));r['seal_receipt_id']=uid('mixed');bad('initial_bind_mixed_seal','BindReceipt',r)
r=body('AddendumLookupBound');r.pop('receipt_sha256');bad('bound_missing_receipt_digest','LookupResponse',r)
r=body('AddendumLookupBound');r['receipt_kind']='release';bad('bound_wrong_receipt_kind','LookupResponse',r)
r=body('AddendumLookupUnknown');r.update(receipt_id=uid('invented'),receipt_sha256=h(b'invented'),receipt_kind='bind');bad('unknown_cannot_publish_receipt','LookupResponse',r)
r=body('AddendumResponseBound');r['receipt']['signature'][0]=256;bad('signature_not_octets','ReceiptResponse',r)
(root/'negative-addendum.json').write_text(json.dumps(negative,indent=2)+'\n')
manifest=dict(contract='42ae960e',positive=positive,negative='negative-addendum.json',containers=containers,test_only_ed25519_seed_hex=seed.hex(),pending=['canonical_provider_creation_result_record_and_exact_result_sha256_mapping','host_retirement_authority_backing_record_and_resolver','real_host_evidence_for_bound_closed_and_scope_stopped','release_observation_storage_and_authorized_resolution_details'])
(root/'addendum-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
