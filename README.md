# Portal — on-chain program (verification mirror)

This repo contains only the Anchor smart contract source for [Portal](https://portal.gripe), published solely so third-party verifiers (e.g. [OtterSec](https://osec.io/) / Solscan) can independently rebuild the program and confirm it matches what's deployed on-chain.

The full Portal application (signalling server, face recognition service, web client, business/legal docs) lives in a private repository and is not part of this mirror.

- **Program ID**: `75vZMouaNixrw4zk1rohwMyHCkPZU7odD5crg6goWjM6`
- **Network**: Solana mainnet-beta
- **Framework**: Anchor 1.0.2

## Verify it yourself

```
solana-verify verify-from-repo \
  --program-id 75vZMouaNixrw4zk1rohwMyHCkPZU7odD5crg6goWjM6 \
  https://github.com/maxtindall/portal-program-verify \
  --library-name portal
```
