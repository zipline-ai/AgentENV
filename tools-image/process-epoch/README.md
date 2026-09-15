# Process epoch build inputs

`build-inputs.json` pins the inspected guest source for the upcoming cooperative
patch. It is an unsigned build-input record, **not** a release manifest, runtime
capability, authenticated descriptor or evidence that the guest implements a fence.
The ordinary tools image build is unchanged in this first commit.

The patched build must later record source, ordered patch hashes, generated protocol
hash, and compiled binary/image hashes. Operator approval and verified provisioning
identify the initial artifact only. Root in the guest can modify its behavior and
forge guest receipts; neither the manifest nor a node signature over a guest report
proves execution cessation. Only independently conclusive host cessation of the
exact authorized domain, including absence of an executing second copy, may provide
that security evidence. Warm per-process handover is unavailable.
