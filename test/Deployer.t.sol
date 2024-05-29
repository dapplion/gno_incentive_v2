// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {Deployer} from "../src/Deployer.sol";

contract DeployerTest is Test {
    Deployer public deployer;

    function setUp() public {
        deployer = new Deployer();
    }

    function test_Increment() public {
        // deployer.deploy();
    }
}
