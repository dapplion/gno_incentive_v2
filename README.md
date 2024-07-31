# DAppNode GNO incentive withdraw contract

Set of smart contracts to support the Gnosis Chain incentive program with DAppNode. Their goal is to align stakers that receive an allocation of GNO tokens to remain engaged with their staking duties.

### Goals

We want to have a withdrawal credentials contract that can do the following:

- Do not allow to claim exited funds before some expiry date
- Allow user to claim staking rewards (partial withdrawals)
- Do not allow consolidations
- Be forwards compatible with any future duty of a withdrawal credentials address

### Implementation

In summary, each staker is assigned a deployment of 2/2 Safe with custom logic:

- Partial withdrawals under some threshold (i.e. 1 GNO) can be forwarded to the beneficiary
- After an expiry date (i.e. 1 year) the Safe can be downgraded to a 1/1 with the beneficiary as sole owner
- Withdrawals over the threshold (i.e. in the case of an exit) require resolution. The contract expects a beacon state proof against a recent state to learn if its validators are exited or not.
  - If the validators are exited before the expiry, forward the funds to the funder (i.e. DAppNode org)
  - If the validators are not exited, forward the funds to the beneficiary

This logic prevent the staker from exiting early and claiming the funds before the expiry date. The resolution via proofs prevents grifting attacks by the funder or 3rd parties if we just checked for amounts. Consider the following scenario: The funder can deposit GNO into the withdrawal contract to activate the condition and claim the user rewards by themselves. 

### Considerations

#### Immediate exit

Withdrawals of value above some threshold require participants to proof the validator's exit status. If the beneficiary exists before the expiry date, the funder can claim the funds back.

#### Consolidations under EIP-7251

Consolidations are triggered by the withdrawal credentials sending a message to a pre-defined smart-contract. Whoever can send consolidations can claim all the funds. Therefore, nor the beneficiary nor the funder can send unilateral consolidations. Forcing consolidation calls to go through a 2/2 Safe achieves it.

#### Innactive until expiry date

A beneficiary could choose to not participate in the network until the expiry date. This strategy is risky as if there's a period of inactivity leak it will acrue heavy penalties. The current implementation does not address this issue.

