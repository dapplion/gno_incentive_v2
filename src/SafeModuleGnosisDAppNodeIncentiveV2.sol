// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "safe-smart-account/contracts/interfaces/IModuleManager.sol";

contract SafeModuleGnosisDAppNodeIncentiveV2 {
    // Ref: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#validator
    uint256 private constant VALIDATOR_PUBKEY_INDEX = 0;
    // Ref: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#validator
    uint256 private constant VALIDATOR_WITHDRAWABLE_EPOCH_INDEX = 7;
    // Ref: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#beaconstate
    uint256 private constant STATE_VALIDATORS_INDEX = 11;

    struct UserInfo {
        // Expiry timestamp
        uint256 expiry;
        // Balance threshold
        uint256 threshold;
        // Array of BLS pubkey hashes
        bytes32[] pubkeyHashes;
    }

    mapping(address => UserInfo) public userInfos;

    function registerSafe(_info UserInfo) public {
        require(userInfos[msg.sender].expiry == 0, "already registered");
        require(_info.expiry > block.timestamp, "must expire in the future");
        userInfos[msg.sender] = _info;
    }

    /**
     * @notice Remove the funder address of withdrawal credentials safe. Can be called by anyone
     * after expiry.
     * @param from Address of Safe to remove funder owner from
     */
    function removeFunderOwner(address from) external {
        UserInfo info = userInfos[from];
        require(info.expiry != 0, "not registered");
        require(info.expiry < block.timestamp, "not expired");
        tx = OwnerManager.removeOwner(prevOwner, funder_address, 1);
        // TODO: Handle return properly if this function reverts
        IModuleManager(_safe).execTransactionFromModule(safe_address, 0, tx, DelegateCall);
    }

    /**
     * @notice Withdraw balance from withdrawal credentials bypassing the Safe 2/2 threshold.
     * Allows the benefactor to withdraw skimmed rewards while under some max value. If the contract
     * holds over `threshold` of balance the caller must provide a proof of the validator's status.
     * If at some validator is exited, the funds are transfered to the funder. Otherwise, the funds
     * are transfered to the benefactor.
     * @param to Address of Safe to withdraw funds from
     * @param exitProofs Optional merkle proofs for validator status
     */
    function withdrawBalance(address from, bytes[] exitProofs) external {
        UserInfo info = userInfos[from];
        require(info.expiry != 0, "not registered");

        address transfer_to;
        if (
            info
                // If past expiry, always transfer to benefactor
                .expiry >= block.timestamp
            // If under threshold, always transfer to benefactor
            || balance < threshold
            // else proof that at least one validator is exited, or all are not exited
            || !isSomeValidatorExited(info.pubkeyHashes, exitProofs)
        ) {
            transfer_to = benefactor;
        } else {
            transfer_to = funder;
        }

        tx = ERC20.transfer(transfer_to, balance);
        // TODO: Handle return properly if this function reverts
        IModuleManager(_safe).execTransactionFromModule(token_address, 0, tx, DelegateCall);
    }

    function isSomeValidatorExited(bytes32[] pubkeyHashes, bytes[] exitProofs) internal {
        // TODO: Should check:
        // Given the following input data:
        // - List of indexes of each validator in the state: uint64[] indexes
        // - List of
        // Given index `N`, check that
        // - `hash_tree_root(state.validators[N].pubkey) == pubkey_hashes[i]`
        // - `hash_tree_root(state.validators[N].pubkey) == pubkey_hashes[i]`
        for (uint256 i = 0; i < pubkey_hashes.length; i++) {
            uint64 withdrawable_epoch = assertValidExitProof(pubkey_hashes[i], exitProofs[i]);
            if (withdrawable_epoch > current_epoch) {
                return true;
            }
        }

        return false;
    }

    /**
     * @notice Validates two beacon chain state proofs of the following properties:
     * - `hash_tree_root(state.validators[index].pubkey) == pubkey_hash`
     * - `state.validators[index].withdrawable_epoch == withdrawable_epoch`
     *
     * Verify each tree independently to not hardcode depths. If beacon chain containers grow, this
     * code won't break as long as as there no change in the ordering of existing properties.
     * If SSZ stable containers are implemented this code will break.
     */
    function assertValidExitProof(bytes32 pubkeyHash, bytes data) internal pure returns (uint64) {
        (
            bytes32[] memory pubkeyProof,
            bytes32[] memory slashedProof,
            bytes32[] memory validatorProof,
            bytes32[] memory stateProof,
            uint64 validator_index,
            uint64 withdrawable_epoch
        ) = abi.decode(data, (bytes32[], bytes32[], bytes32[], bytes32[], uint64, uint64));

        bytes32 validator_root_pk = computeMerkleBranch(pubkey_hash, pubkeyProof, VALIDATOR_PUBKEY_INDEX);
        // TODO: I think this is wrong, beacon chain is little endian
        bytes32 withdrawable_epoch_leaf = abi.encode(withdrawable_epoch);
        bytes32 validator_root_we =
            computeMerkleBranch(withdrawable_epoch_leaf, withdrawable_epoch_proof, VALIDATOR_WITHDRAWABLE_EPOCH_INDEX);
        require(validator_root_pk == validator_root_we, "inconsistent validator proofs");

        bytes32 validators_root = computeMerkleBranch(validator_root_pk, validatorProof, index);
        bytes32 state_root = computeMerkleBranch(validators_root, stateProof, STATE_VALIDATORS_INDEX);

        require(state_root == getEip4788Root(), "invalid_proof");
        return withdrawable_epoch;
    }

    /**
     * @notice Computes a merkle root given a branch of some depth.
     * Ref: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#is_valid_merkle_branch
     */
    function computeMerkleBranch(bytes32 leaf, bytes32[] memory branch, uint64 index) internal pure returns (bytes32) {
        bytes32 value = leaf;
        for (uint64 i = 0; i < branch.length; i++) {
            if ((index / (2 ** i)) % 2 == 1) {
                value = keccak256(abi.encodePacked(branch[i], value));
            } else {
                value = keccak256(abi.encodePacked(value, branch[i]));
            }
        }
        return value;
    }

    function toLittleEndian64(uint64 value) internal pure returns (bytes32 ret) {
        bytes memory result = new bytes(8);
        result[0] = bytes1(uint8(value));
        result[1] = bytes1(uint8(value >> 8));
        result[2] = bytes1(uint8(value >> 16));
        result[3] = bytes1(uint8(value >> 24));
        result[4] = bytes1(uint8(value >> 32));
        result[5] = bytes1(uint8(value >> 40));
        result[6] = bytes1(uint8(value >> 48));
        result[7] = bytes1(uint8(value >> 56));

        // Convert bytes to bytes32 and pad with zeros
        bytes32 paddedResult;
        assembly {
            paddedResult := mload(add(result, 32))
        }
        return paddedResult;
    }
}
