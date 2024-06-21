// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "safe-smart-account/contracts/Safe.sol";
import "safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import "safe-smart-account/contracts/proxies/SafeProxy.sol";
import "./ISBCDepositContract.sol";
import "./GnosisDAppNodeIncentiveV2SafeModuleSetup.sol";
import "./GnosisDAppNodeIncentiveV2SafeModule.sol";
import "./Ownable.sol";

contract GnosisDAppNodeIncentiveV2Deployer is Ownable {
    struct User {
        Safe safe;
        uint16 maxPendingDeposits;
        bool depositsSet;
    }

    struct PendingDeposits {
        bytes pubkeys;
        bytes signatures;
        bytes32[] deposit_data_roots;
    }

    uint256 nonce = 0;
    SafeProxyFactory public proxyFactory;
    Safe public safe;
    GnosisDAppNodeIncentiveV2SafeModule public safeModule;
    GnosisDAppNodeIncentiveV2SafeModuleSetup public safeModuleSetup;
    ISBCDepositContract public depositContract;

    mapping(address => User) public users;
    mapping(address => PendingDeposits) public pendingDeposits;

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

    /**
     * @notice Deploys a safe for a benefactor address. Does not assign any funds to user, not sends any deposit
     * After deployment, funder should communicate the Safe address to the benefactor so they can produce signed
     * deposits and submit them with `submitPendingDeposits`
     */
    function assignSafe(
        address benefactor,
        uint256 expiry,
        uint256 withdrawThreshold,
        uint16 maxPendingDeposits,
        bool autoClaimEnabled
    )
        public
        onlyOwner
        returns (SafeProxy)
    {
        // Only allow a single safe per benefactor address for simplicity
        require(address(users[benefactor].safe) == address(0), "already registered");

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
        users[benefactor] = User(Safe(payable(address(proxy))), maxPendingDeposits, false);

        return proxy;
    }

    /**
     * @notice Deploys a safe for a benefactor address. Does not assign any funds to user, not sends any deposit
     * After deployment, funder should communicate the Safe address to the benefactor so they can produce signed
     * deposits and submit them with `submitPendingDeposits`
     */
    function submitPendingDeposits(
        bytes calldata pubkeys,
        bytes calldata signatures,
        bytes32[] calldata deposit_data_roots
    ) public {
        User storage user = users[msg.sender]; 
        // Only allow a registered user to submit deposits or owner as fallback
        require(address(user.safe) != address(0) || msg.sender == owner(), "not allowed"); 
        // Sanity check lengths, allow to submit less deposits in case MaxEB activates early
        require(pubkeys.length == signatures.length, "not same length");
        require(pubkeys.length == deposit_data_roots.length, "not same length");
        require(pubkeys.length > 0, "empty deposits");
        require(pubkeys.length <= user.maxPendingDeposits, "too many deposits");
        // Only allow to set deposits once
        require(!user.depositsSet, "already set");
        user.depositsSet = true;

        pendingDeposits = PendingDeposits(pubkeys, signatures, deposit_data_roots);
    }

    /**
     * @notice After the owner has verified the deposit conditions it can execute the deposits.
     * The `amountPerDeposit` is left as a variable to allow:
     * - Two step deposit to reduce front-run risk: Do first deposit of 1/32 GNO, second deposit of 31/32 GNO
     * - To be forwards compatible with MaxEB, and allow deposits of consolidated validators.
     */
    function executePendingDeposits(
        address benefactor,
        uint256 amountPerDeposit
    ) public onlyOwner {
        User storage user = users[benefactor]; 
        require(user.depositsSet, "not set");

        PendingDeposits storage depositData = pendingDeposits[benefactor];
        bytes memory withdrawal_credentials = abi.encodePacked(address(user.safe));

        depositContract.batchDeposit(
            depositData.pubkeys,
            withdrawal_credentials,
            depositData.signatures,
            depositData.deposit_data_roots
        );
    }

    /**
     * @notice Allows owner to clear deposits for a benefactor in case they submit wrong data. Benefactor must not
     * be able to submit deposits twice to reduce the risk of front-running the funder.
     */
    function clearPendingDeposits(address benefactor) public onlyOwner {
        User storage user = users[benefactor]; 
        require(user.depositsSet, "not set");
        user.depositsSet = false;
    }
}
