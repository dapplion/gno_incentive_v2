// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "safe-smart-account/contracts/Safe.sol";
import "safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import "safe-smart-account/contracts/proxies/SafeProxy.sol";
import "./GnosisDAppNodeIncentiveV2SafeModuleSetup.sol";
import "./GnosisDAppNodeIncentiveV2SafeModule.sol";
import "./utils/ISBCDepositContract.sol";
import "./utils/Ownable.sol";
import "./utils/IERC20.sol";

contract GnosisDAppNodeIncentiveV2Deployer is Ownable {
    enum Status {
        Pending,
        Submitted,
        Executed
    }

    struct PendingDeposit {
        bytes pubkey;
        bytes signature;
        bytes32 deposit_data_root;
    }

    struct User {
        Safe safe;
        Status status;
        uint16 expectedDepositCount;
        uint256 totalStakeAmount;
        PendingDeposit[] pendingDeposits;
    }

    /// @notice Deployed Safe and registered user
    event RegisteredUser(address benefactor);
    /// @notice User has submitted deposit data
    event SubmitPendingDeposits(address benefactor, uint256 count);

    uint256 nonce = 0;
    SafeProxyFactory public proxyFactory;
    Safe public safe;
    GnosisDAppNodeIncentiveV2SafeModule public safeModule;
    GnosisDAppNodeIncentiveV2SafeModuleSetup public safeModuleSetup;
    ISBCDepositContract public depositContract;

    mapping(address => User) public users;

    constructor(
        SafeProxyFactory _proxyFactory,
        Safe _safe,
        GnosisDAppNodeIncentiveV2SafeModule _safeModule,
        GnosisDAppNodeIncentiveV2SafeModuleSetup _safeModuleSetup,
        ISBCDepositContract _depositContract,
        address owner
    ) Ownable(owner) {
        proxyFactory = _proxyFactory;
        safe = _safe;
        safeModule = _safeModule;
        safeModuleSetup = _safeModuleSetup;
        depositContract = _depositContract;
    }

    function getPendingDeposit(address benefactor, uint256 index)
        external
        view
        returns (bytes memory pubkey, bytes memory signature, bytes32 deposit_data_root)
    {
        User storage user = users[benefactor];
        uint16 expectedDepositCount = user.expectedDepositCount;
        require(expectedDepositCount != 0, "not registered");
        require(index < expectedDepositCount, "index out of bounds");
        PendingDeposit storage pendingDeposit = user.pendingDeposits[index];
        return (pendingDeposit.pubkey, pendingDeposit.signature, pendingDeposit.deposit_data_root);
    }

    /**
     * @notice Deploys a safe for a benefactor address. Does not assign any funds to user, not sends any deposit
     * After deployment, funder should communicate the Safe address to the benefactor so they can produce signed
     * deposits and submit them with `submitPendingDeposits`
     */
    function assignSafe(
        address benefactor,
        uint256 expiry,
        uint256 withdrawThreshold,
        uint16 expectedDepositCount,
        uint256 totalStakeAmount,
        bool autoClaimEnabled
    ) external onlyOwner returns (SafeProxy) {
        // Only allow a single safe per benefactor address for simplicity
        User storage user = users[benefactor];
        require(address(user.safe) == address(0), "already registered");

        address funder = owner();
        address[] memory safeOwners = new address[](2);
        safeOwners[0] = funder;
        safeOwners[1] = benefactor;
        uint256 threshold = 2; // 2/2 multi-sig

        bytes memory setupModulesData = abi.encodeWithSignature(
            "setupModule(address,uint256,uint256,address,address,bool)",
            safeModule,
            expiry,
            withdrawThreshold,
            benefactor,
            funder,
            autoClaimEnabled
        );

        SafeProxy proxy = proxyFactory.createProxyWithNonce(
            address(safe),
            abi.encodeWithSignature(
                "setup(address[],uint256,address,bytes,address,address,uint256,address)",
                // _owners List of Safe owners.
                safeOwners,
                // _threshold Number of required confirmations for a Safe transaction.
                threshold,
                // to Contract address for optional delegate call. Calls setupModules
                address(safeModuleSetup),
                // data Data payload for optional delegate call. Calls setupModules
                setupModulesData,
                // fallbackHandler Handler for fallback calls to this contract
                address(0),
                // paymentToken Token that should be used for the payment (0 is ETH)
                address(0),
                // payment Value that should be paid
                uint256(0),
                // paymentReceiver Address that should receive the payment (or 0 if tx.origin)
                address(0)
            ),
            nonce
        );
        nonce += 1;

        // Register safe to allow submitting pending deposits
        user.safe = Safe(payable(address(proxy)));
        user.status = Status.Pending;
        user.expectedDepositCount = expectedDepositCount;
        user.totalStakeAmount = totalStakeAmount;
        delete user.pendingDeposits;

        emit RegisteredUser(benefactor);

        return proxy;
    }

    /**
     * @notice User submits signed deposit data for latter execution
     */
    function submitPendingDeposits(
        bytes calldata pubkeys,
        bytes calldata signatures,
        bytes32[] calldata deposit_data_roots
    ) external {
        _submitPendingDeposits(msg.sender, pubkeys, signatures, deposit_data_roots);
    }

    /**
     * @notice Owner can submit deposit data on behalf of user
     */
    function submitPendingDepositsFor(
        address benefactor,
        bytes calldata pubkeys,
        bytes calldata signatures,
        bytes32[] calldata deposit_data_roots
    ) external onlyOwner {
        _submitPendingDeposits(benefactor, pubkeys, signatures, deposit_data_roots);
    }

    /**
     * @notice Register pending deposits for latter offchain validation and execution
     */
    function _submitPendingDeposits(
        address benefactor,
        bytes calldata pubkeys,
        bytes calldata signatures,
        bytes32[] calldata deposit_data_roots
    ) internal {
        User storage user = users[benefactor];
        // Only allow a registered user to submit deposits
        require(address(user.safe) != address(0), "not registered");
        // Sanity check lengths, allow to submit less deposits in case MaxEB activates early
        uint256 count = deposit_data_roots.length;
        require(count == pubkeys.length / 48, "not same length");
        require(count == signatures.length / 96, "not same length");
        require(count == user.expectedDepositCount, "not expected deposit count");
        require(pubkeys.length % 48 == 0, "Invalid pubkeys length");
        require(signatures.length % 96 == 0, "Invalid signatures length");
        // Only allow to set deposits once
        require(user.status == Status.Pending, "already submitted");
        user.status = Status.Submitted;

        for (uint256 i = 0; i < count; ++i) {
            bytes memory pubkey = bytes(pubkeys[i * 48:(i + 1) * 48]);
            bytes memory signature = bytes(signatures[i * 96:(i + 1) * 96]);

            PendingDeposit memory deposit =
                PendingDeposit({pubkey: pubkey, signature: signature, deposit_data_root: deposit_data_roots[i]});
            user.pendingDeposits.push(deposit);
        }

        emit SubmitPendingDeposits(msg.sender, count);
    }

    /**
     * @notice After the owner has verified the deposit conditions it can execute the deposits.
     */
    function executePendingDeposits(address benefactor) external onlyOwner {
        User storage user = users[benefactor];
        require(user.status == Status.Submitted, "not submitted status");
        user.status = Status.Executed;

        bytes memory withdrawal_credentials = abi.encodePacked(uint8(1), bytes3(0), bytes8(0), address(user.safe));

        // Allow deposit contract to spend withdrawal token once
        IERC20 stake_token = IERC20(depositContract.stake_token());
        if (stake_token.allowance(address(this), address(depositContract)) < type(uint256).max) {
            stake_token.approve(address(depositContract), type(uint256).max);
        }

        // count is bounded by funder set value `maxPendingDeposits`. Funder should validate that the count of deposits
        // is correct before calling this function.
        uint256 count = user.expectedDepositCount;
        uint256 stakeAmountPerDeposit = user.totalStakeAmount / count;

        // Implement a manual batchDeposit for have custom stake amounts
        // No need to validate bytes length, as they are checked in submitPendingDeposits
        for (uint256 i = 0; i < count; ++i) {
            // No required to limit stakeAmountPerDeposit here. We want flexibility to support MaxEB. If funder
            // makes an operational error and over-deposits, it can claim the funds back before expiry date.
            depositContract.deposit(
                user.pendingDeposits[i].pubkey,
                withdrawal_credentials,
                user.pendingDeposits[i].signature,
                user.pendingDeposits[i].deposit_data_root,
                stakeAmountPerDeposit
            );
        }
    }

    /**
     * @notice Allows owner to clear deposits for a benefactor in case they submit wrong data. Benefactor must not
     * be able to submit deposits twice to reduce the risk of front-running the funder.
     */
    function clearPendingDeposits(address benefactor) external onlyOwner {
        User storage user = users[benefactor];
        require(address(user.safe) != address(0), "not registered");
        require(user.status != Status.Pending, "already pending");
        user.status = Status.Pending;
        delete user.pendingDeposits;
    }
}
