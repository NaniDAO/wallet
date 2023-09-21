#!/bin/bash
source .env.local

echo "Deploying WalletFactory..."

forge create --rpc-url $BASEGOERLI_RPC --private-key $PRIVATE_KEY src/WalletFactory.sol:WalletFactory --etherscan-key $BASESCAN_KEY --verify

echo "Deployment completed."

