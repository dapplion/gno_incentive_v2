// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import "safe-smart-account/contracts/Safe.sol";
import "safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {GnosisDAppNodeIncentiveV2Deployer} from "../src/GnosisDAppNodeIncentiveV2Deployer.sol";
import {GnosisDAppNodeIncentiveV2SafeModuleSetup} from "../src/GnosisDAppNodeIncentiveV2SafeModuleSetup.sol";
import {GnosisDAppNodeIncentiveV2SafeModule} from "../src/GnosisDAppNodeIncentiveV2SafeModule.sol";

contract GnosisDAppNodeIncentiveV2DeployerTest is Test {
    GnosisDAppNodeIncentiveV2Deployer public deployer;

    function setUp() public {
        uint256 genesisTime = 160000000;
        uint256 secondsPerEpoch = 5 * 16;
        address withdrawalToken = address(0);
        address eip4788Contract = address(0);

        SafeProxyFactory proxy = new SafeProxyFactory();
        Safe safe = new Safe();
        GnosisDAppNodeIncentiveV2SafeModule safeModule = new GnosisDAppNodeIncentiveV2SafeModule(
            genesisTime,
            secondsPerEpoch,
            withdrawalToken,
            eip4788Contract
        );
        GnosisDAppNodeIncentiveV2SafeModuleSetup safeModuleSetup = new GnosisDAppNodeIncentiveV2SafeModuleSetup();
        deployer = new GnosisDAppNodeIncentiveV2Deployer(
            proxy,
            safe,
            safeModule,
            safeModuleSetup
        );
    }

    function test_deploy() public {
        address funder = vm.addr(1);
        address benefactor = vm.addr(2);
        address[] memory funder_benefactor = new address[](2);
        funder_benefactor[0] = funder;
        funder_benefactor[1] = benefactor;

        uint256 expiry = block.timestamp + 365 days;
        bytes32[] memory pubkeyHashes = new bytes32[](3);
        pubkeyHashes[0] = bytes32(uint256(0xaa));
        pubkeyHashes[1] = bytes32(uint256(0xbb));
        pubkeyHashes[2] = bytes32(uint256(0xcc));

        deployer.deploy(
            funder_benefactor,
            expiry,
            pubkeyHashes
        );
    }
}
