// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "safe-smart-account/contracts/Safe.sol";
import "safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import "safe-smart-account/contracts/proxies/SafeProxy.sol";

contract Deployer {
    uint256 nonce = 0;

    function deploy(SafeProxyFactory proxyFactory, address gnosisSafe, address funder, address benefactor) public {
        uint256 threshold = 2;
        address[2] memory owners;
        owners[0] = benefactor;
        owners[1] = funder;

        SafeProxy proxy = proxyFactory.createProxyWithNonce(
            gnosisSafe,
            abi.encodeWithSignature(
                "setup(address[],uint256,address,bytes,address,address,uint256,address)",
                // _owners List of Safe owners.
                owners,
                // _threshold Number of required confirmations for a Safe transaction.
                threshold,
                // to Contract address for optional delegate call. Calls setupModules
                address(0),
                // data Data payload for optional delegate call. Calls setupModules
                "",
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
    }
}
