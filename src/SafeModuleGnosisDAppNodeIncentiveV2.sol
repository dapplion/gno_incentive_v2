// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "safe-smart-account/contracts/Safe.sol";
import "safe-smart-account/contracts/common/Enum.sol";

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
}

contract SafeModuleGnosisDAppNodeIncentiveV2 {
    // Ref: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#validator
    uint256 private constant VALIDATOR_PUBKEY_INDEX = 0;
    // Ref: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#validator
    uint256 private constant VALIDATOR_WITHDRAWABLE_EPOCH_INDEX = 7;
    // Ref: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#beaconstate
    uint256 private constant STATE_VALIDATORS_INDEX = 11;

    // This network's beacon genesis time
    uint256 private genesisTime;
    // This network's SECONDS_PER_SLOT * SLOTS_PER_EPOCH constant
    uint256 private secondsPerEpoch;
    // Funder address that will be removed on removeFunderOwner
    address private funder;
    // Address of the token to claim withdrawals from
    IERC20 private withdrawalToken;
    // EIP-4788 contract
    address private eip4788Contract;

    struct UserInfo {
        // Expiry timestamp
        uint256 expiry;
        // Balance threshold
        uint256 threshold;
        // Benefactor address
        address benefactor;
        // Funder address
        address funder;
        // Array of BLS pubkey hashes
        bytes32[] pubkeyHashes;
    }

    mapping(Safe => UserInfo) public userInfos;

    function registerSafe(UserInfo calldata _info) public {
        Safe sender = Safe(payable(msg.sender));
        require(userInfos[sender].expiry == 0, "already registered");
        require(_info.expiry > block.timestamp, "must expire in the future");
        userInfos[sender] = _info;
    }

    /**
     * @notice Remove the funder address of withdrawal credentials safe. Can be called by anyone
     * after expiry.
     * @param from Address of Safe to remove funder owner from
     */
    function removeFunderOwner(Safe from) external {
        UserInfo storage info = userInfos[from];
        require(info.expiry != 0, "not registered");
        require(info.expiry < block.timestamp, "not expired");
        bytes memory data = abi.encodeWithSignature("removeOwner(address,address,uint256)", funder, funder, 1);
        require(
            from.execTransactionFromModule(address(from), 0, data, Enum.Operation.DelegateCall),
            "error safe exec removeOwner"
        );
    }

    /**
     * @notice Withdraw balance from withdrawal credentials bypassing the Safe 2/2 threshold.
     * Allows the benefactor to withdraw skimmed rewards while under some max value. If the contract
     * holds over `threshold` of balance the caller must provide a proof of the validator's status.
     * If at some validator is exited, the funds are transfered to the funder. Otherwise, the funds
     * are transfered to the benefactor.
     * @param from Address of Safe to withdraw funds from
     * @param exitProofs Optional merkle proofs for validator status
     */
    function withdrawBalance(Safe from, bytes[] calldata exitProofs) external {
        UserInfo storage info = userInfos[from];
        require(info.expiry != 0, "not registered");
        uint256 balance = withdrawalToken.balanceOf(address(from));

        address transfer_to;
        if (
            info
                // If past expiry, always transfer to benefactor
                .expiry >= block.timestamp
            // If under threshold, always transfer to benefactor
            || balance < info.threshold
            // else proof that at least one validator is exited, or all are not exited
            || !isSomeValidatorExited(info.pubkeyHashes, exitProofs)
        ) {
            transfer_to = info.benefactor;
        } else {
            transfer_to = info.funder;
        }

        bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", transfer_to, balance);
        require(
            Safe(from).execTransactionFromModule(address(withdrawalToken), 0, data, Enum.Operation.Call),
            "error safe exec transfer"
        );
    }

    /**
     * @notice Given a pre-registered list of pubkey hashes, checks that a list of exitProofs are correct
     * and then checks if any of the validator records corresponding to the pubkey hashes are withdrawn
     */
    function isSomeValidatorExited(bytes32[] storage pubkeyHashes, bytes[] calldata exitProofs)
        internal
        returns (bool)
    {
        bytes32 expectedStateRoot = getEip4788Root();

        for (uint256 i = 0; i < pubkeyHashes.length; i++) {
            uint64 withdrawableEpoch = assertValidExitProof(pubkeyHashes[i], exitProofs[i], expectedStateRoot);
            if (withdrawableEpoch > getCurrentEpoch()) {
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
    function assertValidExitProof(bytes32 pubkeyHash, bytes calldata data, bytes32 expectedStateRoot)
        internal
        pure
        returns (uint64)
    {
        (
            bytes32[] memory pubkeyProof,
            bytes32[] memory withdrawableEpochProof,
            bytes32[] memory validatorProof,
            bytes32[] memory stateProof,
            uint64 validatorIndex,
            uint64 withdrawableEpoch
        ) = abi.decode(data, (bytes32[], bytes32[], bytes32[], bytes32[], uint64, uint64));

        bytes32 validatorRootPk = computeMerkleBranch(pubkeyHash, pubkeyProof, VALIDATOR_PUBKEY_INDEX);
        // TODO: I think this is wrong, beacon chain is little endian
        bytes32 withdrawableEpochLeaf = toLittleEndianLeaf(withdrawableEpoch);
        bytes32 validatorRootWe =
            computeMerkleBranch(withdrawableEpochLeaf, withdrawableEpochProof, VALIDATOR_WITHDRAWABLE_EPOCH_INDEX);
        require(validatorRootPk == validatorRootWe, "inconsistent validator proofs");

        bytes32 validatorsRoot = computeMerkleBranch(validatorRootPk, validatorProof, validatorIndex);
        bytes32 stateRoot = computeMerkleBranch(validatorsRoot, stateProof, STATE_VALIDATORS_INDEX);

        require(stateRoot == expectedStateRoot, "invalid_proof");
        return withdrawableEpoch;
    }

    /**
     * @notice Computes a merkle root given a branch of some depth.
     * Ref: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#is_valid_merkle_branch
     */
    function computeMerkleBranch(bytes32 leaf, bytes32[] memory branch, uint256 index)
        internal
        pure
        returns (bytes32)
    {
        bytes32 value = leaf;
        for (uint256 i = 0; i < branch.length; i++) {
            if ((index / (2 ** i)) % 2 == 1) {
                value = keccak256(abi.encodePacked(branch[i], value));
            } else {
                value = keccak256(abi.encodePacked(value, branch[i]));
            }
        }
        return value;
    }

    function toLittleEndianLeaf(uint64 value) internal pure returns (bytes32) {
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

    function getEip4788Root() internal returns (bytes32) {
        (bool success, bytes memory data) = eip4788Contract.call(abi.encode(block.timestamp));
        require(success, "EIP4788 call failed");
        return abi.decode(data, (bytes32));
    }

    function getCurrentEpoch() internal view returns (uint256) {
        return (block.timestamp - genesisTime) / secondsPerEpoch;
    }
}
