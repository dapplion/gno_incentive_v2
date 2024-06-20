// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import "safe-smart-account/contracts/Safe.sol";
import "safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {GnosisDAppNodeIncentiveV2Deployer} from "../src/GnosisDAppNodeIncentiveV2Deployer.sol";
import {GnosisDAppNodeIncentiveV2SafeModuleSetup} from "../src/GnosisDAppNodeIncentiveV2SafeModuleSetup.sol";
import {GnosisDAppNodeIncentiveV2SafeModule} from "../src/GnosisDAppNodeIncentiveV2SafeModule.sol";
import {UnsafeERC20} from "./mocks/ERC20.sol";
import {EIP4788Mock} from "./mocks/EIP4788Mock.sol";

contract GnosisDAppNodeIncentiveV2DeployerTest is Test {
    GnosisDAppNodeIncentiveV2Deployer public deployer;
    GnosisDAppNodeIncentiveV2SafeModule public safeModule;
    UnsafeERC20 public withdrawalToken;
    uint256 withdrawThreshold = 3 ether;
    uint256 expiryDuration = 365 days;
    address funder;
    address benefactor;

    function setUp() public {
        withdrawalToken = new UnsafeERC20("GNO", "GNO");

        SafeProxyFactory proxy = new SafeProxyFactory();
        Safe safeImplementation = new Safe();
        safeModule = new GnosisDAppNodeIncentiveV2SafeModule(address(withdrawalToken));
        GnosisDAppNodeIncentiveV2SafeModuleSetup safeModuleSetup = new GnosisDAppNodeIncentiveV2SafeModuleSetup();
        deployer = new GnosisDAppNodeIncentiveV2Deployer(proxy, safeImplementation, safeModule, safeModuleSetup);

        // Re-usable addresses
        funder = vm.addr(1);
        benefactor = vm.addr(2);
    }

    function deploySafeProxy() internal returns (Safe) {
        address[] memory funder_benefactor = new address[](2);
        funder_benefactor[0] = funder;
        funder_benefactor[1] = benefactor;

        uint256 expiry = block.timestamp + expiryDuration;
        bytes32[] memory pubkeyHashes = new bytes32[](3);
        pubkeyHashes[0] = bytes32(uint256(0xaa));
        pubkeyHashes[1] = bytes32(uint256(0xbb));
        pubkeyHashes[2] = bytes32(uint256(0xcc));

        SafeProxy proxy = deployer.deploy(funder_benefactor, expiry, withdrawThreshold, pubkeyHashes);
        Safe safe = Safe(payable(address(proxy)));
        // Sanity check
        (,, address retrievedBenefactor, address retrievedFunder,,) = safeModule.getUserInfo(safe);
        assertEq(retrievedBenefactor, benefactor, "Benefactor address does not match");
        assertEq(retrievedFunder, funder, "Funder address does not match");
        assertFalse(isExpired(safe), "should not be expired");
        
        return safe;
    }

    function test_deploy() public {
        Safe safe = deploySafeProxy();
    }

    function isExpired(Safe safe) public returns (bool) {
        (uint256 expiry,,,,,) = safeModule.getUserInfo(safe);
        return block.timestamp >= expiry;
    }

    function mintAndWithdraw(Safe safe, uint256 amount) public {
        withdrawalToken.mint(address(safe), amount);
        safeModule.withdrawBalance(safe, false);
    }

    // Tests that if the contract has < threshold a withdraw call without proof succeeds and the balance
    // goes to the benefactor. Note that anyone can call `withdrawBalance` so we don't need to assert
    // access control here, the funder will never gets funds.
    function test_benefactor_can_withdraw_under_threshold() public {
        Safe safe = deploySafeProxy();

        assertEq(withdrawalToken.balanceOf(benefactor), 0, "not initial zero balance");
        uint256 amount = withdrawThreshold - 1;
        mintAndWithdraw(safe, amount);
        assertEq(withdrawalToken.balanceOf(benefactor), amount, "benefactor did not got funds");
    }

    // Tests that if the balance is >= threshold any call to withdrawBalance reverts if it has no proofs
    function test_noone_can_withdraw_over_threshold_with_empty_proofs() public {
        Safe safe = deploySafeProxy();

        uint256 amount = withdrawThreshold + 1;
        withdrawalToken.mint(address(safe), amount);
        vm.expectRevert(bytes("exitProofs length"));
        safeModule.withdrawBalance(safe, false);
    }

    // Tests that if the contract has < threshold a withdraw call without proof succeeds and the balance
    // goes to the benefactor. Note that anyone can call `withdrawBalance` so we don't need to assert
    // access control here, the funder will never gets funds.
    function test_benefactor_can_withdraw_after_expiry_under_threshold() public {
        Safe safe = deploySafeProxy();
        vm.warp(block.timestamp + expiryDuration + 1);
        assertTrue(isExpired(safe), "should be expired");

        uint256 amount = withdrawThreshold - 1;
        mintAndWithdraw(safe, amount);
    }

    function test_benefactor_can_withdraw_after_expiry_over_threshold() public {
        Safe safe = deploySafeProxy();
        vm.warp(block.timestamp + expiryDuration + 1);
        assertTrue(isExpired(safe), "should be expired");

        uint256 amount = withdrawThreshold + 1;
        mintAndWithdraw(safe, amount);
    }

    // Assert safe 2/2 logic. We trust on Safe's implementation but this tests ensure that the withdraw
    // credentials account can't submit consolidation messages without the approval of both funder and
    // benefactor
    function test_benefactor_can_not_execute_transactions() public {
        // TODO
    }

    function test_funder_can_not_execute_transactions() public {
        // TODO
    }

    function test_funder_and_benefactor_can_execute_transactions() public {
        // TODO
    }

    // Test that exit proof is correct
    function test_benefactor_can_withdraw_exit_proof_not_exited() public {
        // TODO
    }

    function test_funder_can_withdraw_exit_proof_exited() public {
        // TODO
    }

    // Test various invalid proof cases
    function test_invalid_exit_proof() public {
        // TODO
    }
}
