// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "safe-smart-account/contracts/Safe.sol";
import "safe-smart-account/contracts/common/Enum.sol";
import "./utils/IERC20.sol";

contract GnosisDAppNodeIncentiveV2SafeModule {
    // Address of the token to claim withdrawals from
    IERC20 private withdrawalToken;

    struct UserInfo {
        // Expiry timestamp
        uint256 expiry;
        // Balance threshold
        uint256 withdrawThreshold;
        // Benefactor address
        address benefactor;
        // Funder address
        address funder;
        // If auto-claim is enabled for this contract
        bool autoClaimEnabled;
        // If funder has terminated this program
        bool terminated;
    }

    mapping(Safe => UserInfo) public userInfos;

    constructor(address _withdrawalToken) {
        withdrawalToken = IERC20(_withdrawalToken);
    }

    function getUserInfo(Safe _safe) external view returns (uint256, uint256, address, address, bool, bool) {
        UserInfo storage info = userInfos[_safe];
        require(info.expiry > 0, "not registered");
        return
            (info.expiry, info.withdrawThreshold, info.benefactor, info.funder, info.autoClaimEnabled, info.terminated);
    }

    function registerSafe(
        uint256 expiry,
        uint256 withdrawThreshold,
        address benefactor,
        address funder,
        bool autoClaimEnabled
    ) external {
        // Safe to register with msg.sender. Safe address is deterministic on it initializer payload. The target Safe
        // that we will deploy is owned by benefactor and funder, and includes init code to call this function
        // on deployment. Any change on init code or owners will result in a different Safe address.
        Safe sender = Safe(payable(msg.sender));
        require(withdrawThreshold >= 0.1 ether, "withdrawThreshold too low");
        require(userInfos[sender].expiry == 0, "already registered");
        require(expiry > block.timestamp, "must expire in the future");
        userInfos[sender] = UserInfo(expiry, withdrawThreshold, benefactor, funder, autoClaimEnabled, false);
    }

    /**
     * @notice Allow benefactor to enable auto-claim to allow any automated party to claim funds to benefactor.
     * @param from Address of Safe to enable auto claim
     */
    function setAutoClaim(Safe from, bool _autoClaimEnabled) external {
        UserInfo storage info = userInfos[from];
        require(info.expiry != 0, "not registered");
        require(msg.sender == info.benefactor || msg.sender == info.funder, "only benefactor or funder");
        // Note: no need to check for terminated, autoClaim has no influence on a terminated program
        info.autoClaimEnabled = _autoClaimEnabled;
    }

    /**
     * @notice Remove the funder address of withdrawal credentials safe. Can be called by anyone
     * after expiry. This function may be called multiple times but will not succeed as funder is already removed.
     * @param from Address of Safe to remove funder owner from
     */
    function removeFunderOwner(Safe from) external {
        UserInfo storage info = userInfos[from];
        require(info.expiry != 0, "not registered");
        require(!info.terminated, "terminated");
        require(block.timestamp >= info.expiry, "not expired");
        bytes memory data = abi.encodeWithSignature("removeOwner(address,address,uint256)", address(1), info.funder, 1);
        require(
            from.execTransactionFromModule(address(from), 0, data, Enum.Operation.Call), "error safe exec removeOwner"
        );
    }

    /**
     * @notice Mark this incentive program as failed and terminated. Only funder can access funds and may choose
     * to exit the validators
     * @param from Address of Safe to terminate
     */
    function terminate(Safe from) external {
        UserInfo storage info = userInfos[from];
        require(info.expiry != 0, "not registered");
        require(block.timestamp < info.expiry, "already expired");
        require(msg.sender == info.funder, "only funder");
        // No need to check for already terminated, funder has no reason to call this function multiple times and will have
        // no effect as benefactor is already removed

        // Mark as terminated
        info.terminated = true;

        // Remove benefactor
        bytes memory data =
            abi.encodeWithSignature("removeOwner(address,address,uint256)", info.funder, info.benefactor, 1);
        require(
            from.execTransactionFromModule(address(from), 0, data, Enum.Operation.Call), "error safe exec removeOwner"
        );
    }

    /**
     * @notice Withdraw balance from withdrawal credentials bypassing the Safe 2/2 threshold.
     * Allows the benefactor to withdraw skimmed rewards while under some threshold. If the contract
     * holds over `threshold` of balance the funder must resolve the case by setting `funderOnlyTransferToSelf`
     * - If the benefactor has broken the incentive program rules, set `funderOnlyTransferToSelf` to true, and
     *   consider terminating the contract
     * - If the benefactor has NOT broken the incentive program rules (i.e. someone transfered extra GNO to
     *      this address for some reason, set `funderOnlyTransferToSelf` to false to resolve the dispute.
     * @param from Address of Safe to withdraw funds from
     * @param funderOnlyTransferToSelf Optional bool used by funder only to resolve a balance over threshold case
     */
    function withdrawBalance(Safe from, bool funderOnlyTransferToSelf) external {
        UserInfo storage info = userInfos[from];
        require(info.expiry != 0, "not registered");
        uint256 balance = withdrawalToken.balanceOf(address(from));
        // Note: transferTo can only be set to either funder or benefactor
        address transferTo;

        if (info.terminated) {
            // If this program has been terminated allow anyone to auto claim to funder
            transferTo = info.funder;
        } else if (block.timestamp < info.expiry && balance > info.withdrawThreshold) {
            // During incentive program, contract has too much balance indicating a potential exit.
            // Only allow funder to resolve this case.
            require(msg.sender == info.funder, "only funder");
            if (funderOnlyTransferToSelf) {
                transferTo = info.funder;
            } else {
                transferTo = info.benefactor;
            }
        } else {
            // Here either incentive program has expired, or there's a small partial withdrawal (no exit).
            // Allow anyone to trigger if auto claim enabled, else only the benefactor.
            if (!info.autoClaimEnabled) {
                require(msg.sender == info.benefactor, "only benefactor");
            }
            transferTo = info.benefactor;
        }

        bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", transferTo, balance);
        require(
            Safe(from).execTransactionFromModule(address(withdrawalToken), 0, data, Enum.Operation.Call),
            "error safe exec transfer"
        );
    }
}
