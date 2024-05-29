// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "safe-smart-account/contracts/Safe.sol";

contract Deployer {
    uint256 public number;

    function deploy(uint256 newNumber) public {
        GnosisSafeProxy proxy = proxyFactory.createProxy(
            address(gnosisSafe),
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
            )
        );
        proxy.enableModule(module_address);
    }

    function increment() public {
        number++;
    }
}
