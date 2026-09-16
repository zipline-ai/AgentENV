#!/usr/bin/env python3
"""Add response fixtures without rewriting any earlier frozen SignedRecord."""
import copy
import hashlib
import json
import pathlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

root = pathlib.Path(__file__).resolve().parents[1] / 'testdata/process-epoch-vectors/v1'
schema = json.loads((root / 'schema.json').read_text())
key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
def canonical(value): return json.dumps(value, separators=(',', ':')).encode()
def digest(value): return hashlib.sha256(value).hexdigest()
def fixture(name): return json.loads((root / (name + '.json')).read_text())
def body(name): return json.loads(bytes.fromhex(fixture(name)['canonical_hex']))
def record(name):
    v = fixture(name)
    return {k: list(bytes.fromhex(v[f])) for k, f in [('body', 'canonical_hex'), ('envelope', 'envelope_hex'), ('signature', 'signature_hex')]}
def sign(value, request_hash, nonce):
    b = canonical(value)
    e = json.loads(bytes.fromhex(fixture('BindReceipt')['envelope_hex']))
    e.update(domain='agentenv-process-epoch/node-response/v1', audience='controller/fixture', request_sha256=request_hash, body_sha256=digest(b), nonce=nonce)
    eb = canonical(e)
    return dict(body=list(b), envelope=list(eb), signature=list(key.sign(e['domain'].encode() + b'\0' + eb)))
positive = []
contexts = []
def emit(name, kind, value, request_hash):
    r = sign(value, request_hash, digest(name.encode()))
    b, e = bytes(r['body']), bytes(r['envelope'])
    v = dict(name=name, kind=kind, canonical_hex=b.hex(), sha256=digest(b), envelope_hex=e.hex(), signature_input_hex=(b'agentenv-process-epoch/node-response/v1\0'+e).hex(), public_key_hex=fixture('BindReceipt')['public_key_hex'], signature_hex=bytes(r['signature']).hex())
    (root / (name+'.json')).write_text(json.dumps(v, indent=2)+'\n')
    positive.append(name+'.json')
    return r
for source in ['Addendum2Dispatch'+k+o for k in ['Create','Restore'] for o in ['Running','Failed','Unknown']] + ['Addendum2HostCessation']:
    original = record(source)
    rb = json.loads(bytes(original['body']))
    dispatch = 'dispatch_kind' in rb
    kind, state = ('dispatch_result', 'dispatch_completed') if dispatch else ('host_cessation', 'retired')
    operation = rb['operation_id'] if dispatch else rb['retirement_operation_id']
    request_hash = rb['dispatch_request_sha256'] if dispatch else rb['retirement_request_sha256']
    binding = copy.deepcopy(body('InitialBindRequest')['binding'])
    binding.update({k: v for k, v in rb.items() if k in binding})
    binding['operation_id'] = operation
    # Complete the pre-existing fixed-order LookupResponse; the saved request supplies
    # fields that the standalone result intentionally does not duplicate.
    lookup = dict(binding=binding, request_sha256=request_hash, state=state, node_ledger_revision=rb['node_ledger_revision'], receipt_id=operation, receipt_sha256=digest(canonical(original)), receipt_kind=kind)
    name = 'Addendum3'+source.removeprefix('Addendum2')
    node = emit(name+'Lookup', 'LookupResponse', lookup, request_hash)
    response = dict(node=node, receipt=original)
    emit(name+'Response', 'ReceiptResponse', response, request_hash)
    contexts.append(dict(name=name+'Response.json', source=source+'.json', binding=binding, request_sha256=request_hash, nonce=json.loads(bytes(node['envelope']))['nonce'], receipt_kind=kind, state=state, accepted=True))

negative = []
lookup = body('Addendum3DispatchCreateRunningLookup')
for name, change in [('missing_receipt', lambda x: x.pop('receipt_id')), ('wrong_kind', lambda x: x.update(receipt_kind='bind')), ('wrong_state', lambda x: x.update(state='bound'))]:
    x=copy.deepcopy(lookup); change(x)
    negative.append(dict(name=name, kind='LookupResponse', canonical_hex=canonical(x).hex()))
x=body('Addendum3HostCessationLookup'); x['receipt_kind']='dispatch_result'
negative.append(dict(name='retired_wrong_kind',kind='LookupResponse',canonical_hex=canonical(x).hex()))
(root/'negative-addendum-3.json').write_text(json.dumps(negative,indent=2)+'\n')

# Valid canonical wrappers can still be foreign, stale, swapped or guest-signed.
# Expected context remains the saved independently trusted original below.
for label in ['body_digest_reference','changed_operation','changed_request','stale_nonce','foreign_incarnation','guest_impostor','missing_record','changed_record_signature', 'guest_member', 'host_wrong_request', 'host_wrong_incarnation', 'host_guest_impostor']:
    host=label.startswith('host_')
    ctx=copy.deepcopy(contexts[6] if host else contexts[0]); response=body('Addendum3HostCessationResponse' if host else 'Addendum3DispatchCreateRunningResponse')
    lookup=json.loads(bytes(response['node']['body'])); nonce=ctx['nonce']
    if label=='body_digest_reference': lookup['receipt_sha256']=fixture('Addendum2DispatchCreateRunning')['sha256']
    if label=='changed_operation': lookup['binding']['operation_id']=body('Addendum2Retirement')['operation_id']
    if label in ['changed_request', 'host_wrong_request']: lookup['request_sha256']=digest(b'foreign request')
    if label=='stale_nonce': nonce=digest(b'stale nonce')
    if label in ['foreign_incarnation', 'host_wrong_incarnation']: lookup['binding']['runtime_incarnation']=body('Addendum2WrongIncarnation')['runtime_incarnation']
    if label in ['guest_impostor', 'host_guest_impostor']:
        e=bytes(response['receipt']['envelope'])
        response['receipt']['signature']=list(Ed25519PrivateKey.from_private_bytes(bytes(range(32,64))).sign(b'agentenv-process-epoch/node-response/v1\0'+e))
        lookup['receipt_sha256']=digest(canonical(response['receipt']))
    if label=='guest_member': response['guest']=record('Addendum2GuestImpostor')
    if label=='missing_record': response.pop('receipt')
    if label=='changed_record_signature': response['receipt']['signature'][0]^=1
    response['node']=sign(lookup,lookup['request_sha256'],nonce)
    response={k:response[k] for k in ['node','guest','receipt'] if k in response}
    name='Addendum3Reject'+''.join(x.title() for x in label.split('_'))
    emit(name,'ReceiptResponse',response,ctx['request_sha256']); positive.pop()
    ctx.update(name=name+'.json',accepted=False); contexts.append(ctx)
(root/'addendum-3-manifest.json').write_text(json.dumps(dict(positive=positive,negative='negative-addendum-3.json',contexts=contexts,test_only_ed25519_seed_hex=bytes(range(32)).hex()),indent=2)+'\n')
