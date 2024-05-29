// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "safe-smart-account/contracts/Safe.sol";
import "safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import "safe-smart-account/contracts/proxies/SafeProxy.sol";
import "./GnosisDAppNodeIncentiveV2SafeModuleSetup.sol";
import "./GnosisDAppNodeIncentiveV2SafeModule.sol";

contract GnosisDAppNodeIncentiveV2Deployer {
    uint256 nonce = 0;
    SafeProxyFactory private proxyFactory;
    Safe private safe;
    GnosisDAppNodeIncentiveV2SafeModule private safeModule;
    GnosisDAppNodeIncentiveV2SafeModuleSetup private safeModuleSetup;

    constructor(
        SafeProxyFactory _proxyFactory,
        Safe _safe,
        GnosisDAppNodeIncentiveV2SafeModule _safeModule,
        GnosisDAppNodeIncentiveV2SafeModuleSetup _safeModuleSetup
    ) {
        proxyFactory = _proxyFactory;
        safe = _safe;
        safeModule = _safeModule;
        safeModuleSetup = _safeModuleSetup;
    }

    function deploy(
        address funder,
        address benefactor,
        uint256 expiry,
        bytes32[] calldata pubkeyHashes
    ) public returns(SafeProxy) {
        uint256 threshold = 2;
        address[2] memory owners;
        owners[0] = benefactor;
        owners[1] = funder;

        GnosisDAppNodeIncentiveV2SafeModule.UserInfo memory info = GnosisDAppNodeIncentiveV2SafeModule.UserInfo(
            // Expiry timestamp
            expiry,
            // Balance threshold
            threshold,
            // Benefactor address
            benefactor,
            // Funder address
            funder,
            // Array of BLS pubkey hashes
            pubkeyHashes
        );

        bytes memory setupModulesData = abi.encodeWithSignature(
            "setup(address,SafeModuleGnosisDAppNodeIncentiveV2.UserInfo)",
            safeModule, info
        );

        SafeProxy proxy = proxyFactory.createProxyWithNonce(
            address(safe),
            abi.encodeWithSignature(
                "setup(address[],uint256,address,bytes,address,address,uint256,address)",
                // _owners List of Safe owners.
                owners,
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
        return proxy;
    }
}
