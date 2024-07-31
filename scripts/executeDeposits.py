# Script to validate pending deposit data and execute it
#
# Steps:
# - Discover new pending deposits from users, with event GnosisDAppNodeIncentiveV2Deployer.SubmitPendingDeposits
#   - TODO: As optimization remember the last polled block and skip older deposits, and start from deployment
# - Fetch deposit data from contract with getPendingDeposit(beneficiary, index).
# - Validate deposit data:
#   - Signs over correct payload + correct signature
#   - There's no previous deposit for that pubkey
#
# **GnosisDAppNodeIncentiveV2Deployer events**
#
# ```solidity
# event SubmitPendingDeposits(address beneficiary, uint256 count);
# ```
#
# **IDepositContract events**
# 
# ```solidity
# event DepositEvent(bytes pubkey, bytes withdrawal_credentials, bytes amount, bytes signature, bytes index);
# ```
