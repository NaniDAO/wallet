# [Wallet](https://github.com/NaniDAO/wallet)  [![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPL-black.svg)](https://opensource.org/license/agpl-v3/) [![solidity](https://img.shields.io/badge/solidity-%5E0.8.19-black)](https://docs.soliditylang.org/en/v0.8.19/) [![Foundry](https://img.shields.io/badge/Built%20with-Foundry-000000.svg)](https://getfoundry.sh/) ![tests](https://github.com/NaniDAO/wallet/actions/workflows/ci.yml/badge.svg)

Minimal contract wallet with native [EIP-4337](https://eips.ethereum.org/EIPS/eip-4337) support. Hyper-optimized for gas efficiency and cheap relay transactions. Inspired by [Solady](https://github.com/Vectorized/solady/tree/main) Solidity library.

## Getting Started

Build the foundry project with `forge build`. Run tests with `forge test`. Measure gas with `forge snapshot`. Format with `forge fmt`.

## GitHub Actions

Contracts will be tested and gas measured on every push and pull request.

You can edit the CI script in [.github/workflows/ci.yml](./.github/workflows/ci.yml).

## Blueprint

```txt
lib
├─ forge-std — https://github.com/foundry-rs/forge-std
├─ solady - https://github.com/Vectorized/solady 
scripts
├─ Deploy.s.sol — Example Deployment
src
├─ Wallet — Core Wallet Contract
├─ WalletFactory — Wallet Deployer
test
└─ Wallet.t - Tests for Wallet
└─ WalletFactory.t - Tests for Deployer
```

## Disclaimer

_These smart contracts are being provided as is. No guarantee, representation or warranty is being made, express or implied, as to the safety or correctness of the user interface or the smart contracts. They have not been audited and as such there can be no assurance they will work as intended, and users may experience delays, failures, errors, omissions, loss of transmitted information or loss of funds. The creators are not liable for any of the foregoing. Users should proceed with caution and use at their own risk._

See [LICENSE](./LICENSE) for more details.