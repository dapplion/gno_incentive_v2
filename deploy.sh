#!/usr/bin/env bash

# Replace with an address that is script-friendly, and can last the whole duration of the program.
# Must do this actions:
# - Assign safe to user at start of program
# - Terminate safe at end of program
export OWNER=0x0000000000000000000000000000000000000000

### Gnosis network addresses
# Gnosis v1.4.1 https://github.com/safe-global/safe-deployments/blob/bb7f75f6c09dc737b73ee9622a5167591bcab8ac/src/assets/v1.4.1/safe_proxy_factory.json#L7
export PROXY_FACTORY=0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67
# Gnosis v1.4.1 https://github.com/safe-global/safe-deployments/blob/bb7f75f6c09dc737b73ee9622a5167591bcab8ac/src/assets/v1.4.1/safe.json#L7C19-L7C61
export SAFE=0x41675C099F32341bf84BFc5382aF534df5C7461a
# Gnosis deposit contract https://github.com/gnosischain/specs/blob/080abf340bf3a03e7487610a142371d4fe3389cf/consensus/config/gnosis.yaml#L100C27-L100C69
export DEPOSIT_CONTRACT=0x0B98057eA310F4d31F2a452B414647007d1645d9
# Gnosis chain's GNO wrapper token: The return of `state_token` of `DEPOSIT_CONTRACT` https://gnosisscan.io/token/0x9C58BAcC331c9aa871AFD802DB6379a98e80CEdb
export WITHDRAWAL_TOKEN=0x9C58BAcC331c9aa871AFD802DB6379a98e80CEdb

# Expects an env with the variables:
# `ETHERSCAN_API_KEY`: Api key from gnosisscan.io for automatic verification. Free tier works, just login
# `RAW_PRIVATE_KEY`: This script needs a wallet, you can use raw private key, keystore or many other methods,
#                    just check the docs of `forge script --help`.
# `OWNER`: Address of the account that will be the owner / admin of all contracts and take the role of "funder"
#          in the SafeModule. This address should match the address of the wallet sending the transactions.
source .env

# Can't deploy, as I get this error
# ```
# Error:
# Failed to estimate EIP1559 fees. This chain might not support EIP1559, try adding --legacy to your command.
# ```
# So I will set to send legacy transactions
forge script DeployScript \
  -vvvv \
  --rpc-url https://rpc.gnosis.gateway.fm \
  --broadcast \
  --private-key $RAW_PRIVATE_KEY \
  --etherscan-api-key $ETHERSCAN_API_KEY \
  --verify \
  --legacy

