// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import "safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import "safe-smart-account/contracts/proxies/SafeProxy.sol";
import "../src/utils/ISBCDepositContract.sol";
import "../src/GnosisDAppNodeIncentiveV2Deployer.sol";

contract DeployScript is Script {
    function setUp() public {}

    function run() public {
        vm.broadcast();

        address proxyFactory = vm.envAddress("PROXY_FACTORY");
        address safe = vm.envAddress("SAFE");
        address depositContract = vm.envAddress("DEPOSIT_CONTRACT");
        address withdrawalToken = vm.envAddress("WITHDRAWAL_TOKEN");
        address owner = vm.envAddress("OWNER");

        GnosisDAppNodeIncentiveV2Deployer deployer = new GnosisDAppNodeIncentiveV2Deployer(
            SafeProxyFactory(proxyFactory),
            Safe(payable(safe)),
            ISBCDepositContract(depositContract),
            withdrawalToken,
            owner
        );
    }
}
