// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "safe-smart-account/contracts/Safe.sol";
import "safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import "safe-smart-account/contracts/proxies/SafeProxy.sol";
import "./GnosisDAppNodeIncentiveV2SafeModuleSetup.sol";
import "./GnosisDAppNodeIncentiveV2SafeModule.sol";
import "./utils/ISBCDepositContract.sol";
import "./utils/Ownable.sol";
import "./utils/Claimable.sol";
import "./utils/IERC20.sol";

contract GnosisDAppNodeIncentiveV2Deployer is Ownable, Claimable {
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
    event RegisteredUser(address beneficiary, address safe);
    /// @notice User has submitted deposit data
    event SubmitPendingDeposits(address beneficiary, uint256 count);

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
        ISBCDepositContract _depositContract,
        address withdrawalToken,
        address owner
    ) Ownable(owner) {
        proxyFactory = _proxyFactory;
        safe = _safe;
        safeModule = new GnosisDAppNodeIncentiveV2SafeModule(withdrawalToken);
        safeModuleSetup = new GnosisDAppNodeIncentiveV2SafeModuleSetup();
        depositContract = _depositContract;
    }

    function getPendingDeposit(address beneficiary, uint256 index)
        external
        view
        returns (bytes memory pubkey, bytes memory signature, bytes32 deposit_data_root)
    {
        User storage user = users[beneficiary];
        uint16 expectedDepositCount = user.expectedDepositCount;
        require(expectedDepositCount != 0, "not registered");
        require(index < expectedDepositCount, "index out of bounds");
        PendingDeposit storage pendingDeposit = user.pendingDeposits[index];
        return (pendingDeposit.pubkey, pendingDeposit.signature, pendingDeposit.deposit_data_root);
    }

    /**
     * @notice Deploys a safe for a beneficiary address. Does not assign any funds to user, does not send any deposit.
     * After deployment, funder should communicate the Safe address to the beneficiary so they can produce signed
     * deposits and submit them with `submitPendingDeposits`
     * @param expiry UNIX timestamp of when the incentive program ends. After this time the user will take full
     *        ownership of the funds. Should be current timestamp plus one year.
     * @param withdrawThreshold Maximum contract balance in WEI that the beneficiary is able to withdraw on its
     *        own without authorization of the funder. This amount should be strictly less than the minimal
     *        possible withdrawl balance. Note that on incentive programs of more than one index, the beneficiary
     *        can withdraw indexes one by one. So withdrawThreshold should be set to the ejection balance of a
     *        single validator: 0.5 GNO or 500000000000000000 wei
     * @param beneficiary address of the incentive program beneficiary
     * @param autoClaimEnabled beneficiary allows anyone to claim partial withdrawals into the beneficiary address.
     *        A user may prefer to have it set to false for tax reasons or if it wants to strictly control its
     *        flow of value. true/false.
     * @param expectedDepositCount How many single deposit data items the beneficiary is expected to submit. 
     *        For example: 4
     * @param totalStakeAmount Total amount of GNO in WEI that the funder will submit to the deposit contract,
     *        split equally among each deposit data item. Forwards compatible with MaxEB if we want to deposit 
     *        consolidated validators. For example if 4 GNO: 4000000000000000000.
     */
    function assignSafe(
        uint256 expiry,
        uint256 withdrawThreshold,
        address beneficiary,
        bool autoClaimEnabled,
        uint16 expectedDepositCount,
        uint256 totalStakeAmount
    ) external onlyOwner returns (SafeProxy) {
        // Only allow a single safe per beneficiary address for simplicity
        User storage user = users[beneficiary];
        require(address(user.safe) == address(0), "already registered");

        address funder = owner();
        address[] memory safeOwners = new address[](2);
        safeOwners[0] = funder;
        safeOwners[1] = beneficiary;
        uint256 threshold = 2; // 2/2 multi-sig

        bytes memory setupModulesData = abi.encodeWithSignature(
            "setupModule(address,uint256,uint256,address,address,bool)",
            safeModule,
            expiry,
            withdrawThreshold,
            beneficiary,
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

        emit RegisteredUser(beneficiary, address(proxy));

        return proxy;
    }

    /**
     * @notice User submits signed deposit data for later execution. User is expected to submit a specific
     * number of deposits. This number can be retrieved from the public mapping `users` querying by beneficiary
     * address, and checking the property `expectedDepositCount`.
     * @param pubkeys Concatenated bytes of each `pubkey` property of all deposit data JSONs sorted by deposit
     * index. For example, given the pubkeys:
     * - deposit_0.pubkey = 0x1111 (it's actually 48 bytes)
     * - deposit_1.pubkey = 0x2222
     * `pubkeys` must be set to `0x11112222 (it's actually 48*2 bytes)
     * @param signatures Concatenated bytes of each `signature` property of all deposit data JSONs sorted by
     * deposit index (or same order as the pubkeys). The concatenation format is the same as for pubkeys.
     * @param deposit_data_roots Array of the each `deposit_data_root` property of all deposit data JSONs sorted
     * by deposit index (or same order as the pubkeys).
     */
    function submitPendingDeposits(
        bytes calldata pubkeys,
        bytes calldata signatures,
        bytes32[] calldata deposit_data_roots
    ) external {
        _submitPendingDeposits(msg.sender, pubkeys, signatures, deposit_data_roots);
    }

    /**
     * @notice Owner can submit deposit data on behalf of user. Arguments are the same as for `submitPendingDeposits`
     */
    function submitPendingDepositsFor(
        address beneficiary,
        bytes calldata pubkeys,
        bytes calldata signatures,
        bytes32[] calldata deposit_data_roots
    ) external onlyOwner {
        _submitPendingDeposits(beneficiary, pubkeys, signatures, deposit_data_roots);
    }

    /**
     * @notice Register pending deposits for latter offchain validation and execution
     */
    function _submitPendingDeposits(
        address beneficiary,
        bytes calldata pubkeys,
        bytes calldata signatures,
        bytes32[] calldata deposit_data_roots
    ) internal {
        User storage user = users[beneficiary];
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

        emit SubmitPendingDeposits(beneficiary, count);
    }

    /**
     * @notice After the owner has verified the deposit conditions it can execute the deposits.
     */
    function executePendingDeposits(address beneficiary) external onlyOwner {
        User storage user = users[beneficiary];
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
     * @notice Allows owner to clear deposits for a beneficiary in case they submit wrong data. beneficiary must not
     * be able to submit deposits twice to reduce the risk of front-running the funder.
     */
    function clearPendingDeposits(address beneficiary) external onlyOwner {
        User storage user = users[beneficiary];
        require(address(user.safe) != address(0), "not registered");
        require(user.status == Status.Submitted, "not submitted");
        user.status = Status.Pending;
        delete user.pendingDeposits;
    }

    /**
     * @dev Allows to transfer any locked token from this contract.
     * Only owner can call this method.
     * @param _token address of the token, if it is not provided (0x00..00), native coins will be transferred.
     * @param _to address that will receive the locked tokens from this contract.
     */
    function claimTokens(address _token, address _to) external onlyOwner {
        _claimValues(_token, _to);
    }
}
