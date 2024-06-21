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
    GnosisDAppNodeIncentiveV2Deployer deployer;
    GnosisDAppNodeIncentiveV2SafeModule safeModule;
    UnsafeERC20 withdrawalToken;
    uint256 withdrawThreshold = 0.75 ether;
    uint256 amountOverThreshold = 1 ether;
    uint256 amountUnderThreshold = 0.1 ether;
    uint256 expiryDuration = 365 days;
    address funder;
    address benefactor;
    address anyone;
    Safe safe;

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
        anyone = vm.addr(3);

        // Deploy single safe
        safe = deploySafeProxy();
    }

    function deploySafeProxy() internal returns (Safe) {
        address[] memory funder_benefactor = new address[](2);
        funder_benefactor[0] = funder;
        funder_benefactor[1] = benefactor;

        uint256 expiry = block.timestamp + expiryDuration;
        bool autoClaimEnabled = false;

        SafeProxy proxy = deployer.deploy(funder_benefactor, expiry, withdrawThreshold, autoClaimEnabled);
        Safe safe = Safe(payable(address(proxy)));
        // Sanity check
        (,, address retrievedBenefactor, address retrievedFunder,,) = safeModule.getUserInfo(safe);
        assertEq(retrievedBenefactor, benefactor, "Benefactor address does not match");
        assertEq(retrievedFunder, funder, "Funder address does not match");
        assertFalse(isExpired(safe), "should not be expired");
        
        return safe;
    }

    function isExpired(Safe safe) public returns (bool) {
        (uint256 expiry,,,,,) = safeModule.getUserInfo(safe);
        return block.timestamp >= expiry;
    }

    function mintAndWithdraw(Safe safe, uint256 amount) public {
        withdrawalToken.mint(address(safe), amount);
        safeModule.withdrawBalance(safe, false);
    }

    function enableAutoClaim() private {
        vm.prank(benefactor);
        safeModule.setAutoClaim(safe, true);
    }

    function assertBalance(address to, uint256 amount) private {
        assertEq(withdrawalToken.balanceOf(to), amount, "not expected balance");
    }

    function afterExpiry() private {
        vm.warp(block.timestamp + expiryDuration + 1);
    }

    // - with auto claim false, benefactor can withdraw under threshold
    function test_before_expiry_autoclaim_false_benefactor_under_threshold() public {
        withdrawalToken.mint(address(safe), amountUnderThreshold);
        vm.prank(benefactor);
        safeModule.withdrawBalance(safe, false);
        assertBalance(benefactor, amountUnderThreshold);
    }

    // - with auto claim false, anyone reverts
    function test_before_expiry_autoclaim_false_anyone_reverts() public {
        withdrawalToken.mint(address(safe), amountUnderThreshold);
        vm.prank(anyone);
        vm.expectRevert("only benefactor");
        safeModule.withdrawBalance(safe, false);
    }

    // - with auto claim true, anyone can trigger withdraw under threshold
    function test_before_expiry_autoclaim_true_anyone_under_threshold() public {
        enableAutoClaim();
        withdrawalToken.mint(address(safe), amountUnderThreshold);
        vm.prank(anyone);
        safeModule.withdrawBalance(safe, false);
        assertBalance(benefactor, amountUnderThreshold);
    }

    // - before expiry benefactor can not withdraw over threshold
    function test_before_expiry_autoclaim_false_benefactor_over_threshold_revert() public {
        withdrawalToken.mint(address(safe), amountOverThreshold);
        vm.prank(benefactor);
        vm.expectRevert("only funder");
        safeModule.withdrawBalance(safe, false);
    }

    // - after expiry auto claim false benefactor can withdraw above threoshold
    function test_after_expiry_autoclaim_false_benefactor_above_threshold() public {
        afterExpiry();
        withdrawalToken.mint(address(safe), amountOverThreshold);
        vm.prank(benefactor);
        safeModule.withdrawBalance(safe, false);
        assertBalance(benefactor, amountOverThreshold);
    }

    // - after expiry auto claim true anyone can trigger withdraw above threoshold
    function test_after_expiry_autoclaim_true_anyone_above_threshold() public {
        afterExpiry();
        enableAutoClaim();
        withdrawalToken.mint(address(safe), amountOverThreshold);
        vm.prank(anyone);
        safeModule.withdrawBalance(safe, false);
        assertBalance(benefactor, amountOverThreshold);
    }

    // - before expiry funder can trigger withdraw to benefactor above threshold
    function test_before_expiry_funder_above_threshold_to_benefactor() public {
        withdrawalToken.mint(address(safe), amountOverThreshold);
        vm.prank(funder);
        safeModule.withdrawBalance(safe, false);
        assertBalance(benefactor, amountOverThreshold);
    }

    // - before expiry funder can trigger withdraw to funder above threshold
    function test_before_expiry_funder_above_threshold_to_self() public {
        withdrawalToken.mint(address(safe), amountOverThreshold);
        vm.prank(funder);
        safeModule.withdrawBalance(safe, true);
        assertBalance(funder, amountOverThreshold);
    }

    // - funder can terminate before expiry.
    //   - benefactor is no longer owner
    //   - benefactor can not withdraw any amount
    function test_terminate_before_expiry_funder() public {
        vm.prank(funder);
        safeModule.terminate(safe);
        assertBalance(funder, amountOverThreshold);
        // Attempt withdrawals
        withdrawalToken.mint(address(safe), amountUnderThreshold);
        vm.prank(benefactor);
        safeModule.withdrawBalance(safe, false);
    }

    // - funder can not terminate after expiry
    function test_terminate_after_expiry_funder_revert() public {
        afterExpiry();
        vm.prank(funder);
        vm.expectRevert("already expired");
        safeModule.terminate(safe);
    }

    // - anyone can remove funder after expiry
    function test_remove_funder_after_expiry() public {
        afterExpiry();
        vm.prank(anyone);
        safeModule.removeFunderOwner(safe);
    }

    // - anyone can not remove funder before expiry
    function test_remove_funder_before_expiry_revert() public {
        vm.prank(anyone);
        vm.expectRevert("not expired");
        safeModule.removeFunderOwner(safe);
    }

    // - funder and benefactor can 2/2 send a safe transaction
    function test_send_2of2_safe_transaction() public {
        // TODO
    }

    function test_send_1of2_safe_transaction_revert() public {
        // TODO
    }
}
