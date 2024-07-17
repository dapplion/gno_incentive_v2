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
import {ISBCDepositContract} from "../src/utils/ISBCDepositContract.sol";
import {SBCDepositContract} from "./mocks/SBCDepositContract.sol";

contract GnosisDAppNodeIncentiveV2DeployerTest is Test {
    GnosisDAppNodeIncentiveV2Deployer deployer;
    GnosisDAppNodeIncentiveV2SafeModule safeModule;
    UnsafeERC20 withdrawalToken;
    ISBCDepositContract depositContract;
    uint256 withdrawThreshold = 0.75 ether;
    uint256 amountOverThreshold = 1 ether;
    uint256 amountUnderThreshold = 0.1 ether;
    uint256 expiryDuration = 365 days;
    address funder;
    address benefactor;
    address anyone;
    Safe safe;

    function setUp() public {
        // Re-usable addresses
        funder = vm.addr(1);
        benefactor = vm.addr(2);
        anyone = vm.addr(3);

        withdrawalToken = new UnsafeERC20("GNO", "GNO");
        depositContract = ISBCDepositContract(address(new SBCDepositContract(address(withdrawalToken))));

        SafeProxyFactory proxy = new SafeProxyFactory();
        Safe safeImplementation = new Safe();
        deployer = new GnosisDAppNodeIncentiveV2Deployer(
            proxy, safeImplementation, depositContract, address(withdrawalToken), funder
        );
        safeModule = deployer.safeModule();

        // Deploy single safe
        safe = deploySafeProxy(4);
    }

    function deploySafeProxy(uint16 expectedDepositCount) internal returns (Safe) {
        address[] memory funder_benefactor = new address[](2);
        funder_benefactor[0] = funder;
        funder_benefactor[1] = benefactor;

        uint256 expiry = block.timestamp + expiryDuration;
        bool autoClaimEnabled = false;
        uint256 toDepositValue = uint256(expectedDepositCount) * 1 ether;

        vm.prank(funder);
        SafeProxy proxy = deployer.assignSafe(
            expiry, withdrawThreshold, benefactor, autoClaimEnabled, expectedDepositCount, toDepositValue
        );
        Safe safe = Safe(payable(address(proxy)));

        return safe;
    }

    function test_sanity_checks() public {
        // Sanity check
        (,, address retrievedBenefactor, address retrievedFunder,,) = safeModule.getUserInfo(safe);
        assertEq(retrievedBenefactor, benefactor, "Benefactor address does not match");
        assertEq(retrievedFunder, funder, "Funder address does not match");
        assertFalse(isExpired(safe), "should not be expired");
        // Both are owners
        assertTrue(safe.isOwner(benefactor));
        assertTrue(safe.isOwner(funder));
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
        // Attempt withdrawals
        withdrawalToken.mint(address(safe), amountUnderThreshold);
        vm.prank(benefactor);
        safeModule.withdrawBalance(safe, false);
        assertBalance(benefactor, 0);
        assertBalance(funder, amountUnderThreshold);
        // Assert new owners
        assertFalse(safe.isOwner(benefactor));
        assertTrue(safe.isOwner(funder));
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
        // Assert new owners
        assertTrue(safe.isOwner(benefactor));
        assertFalse(safe.isOwner(funder));
    }

    // - anyone can not remove funder before expiry
    function test_remove_funder_before_expiry_revert() public {
        vm.prank(anyone);
        vm.expectRevert("not expired");
        safeModule.removeFunderOwner(safe);
    }

    // - benefactor can not execute pending deposits
    function test_execute_deposits_benefactor_revert() public {
        submitPendingDeposits(4);
        vm.prank(benefactor);
        vm.expectRevert();
        deployer.executePendingDeposits(benefactor);
    }

    // - funder executes deposit before setting, revert
    function test_execute_deposits_funder_before_submit_revert() public {
        vm.prank(funder);
        vm.expectRevert("not submitted status");
        deployer.executePendingDeposits(benefactor);
    }

    // - funder executes deposit after submit one deposit
    function test_execute_deposits_funder_after_submit_single() public {
        benefactor = vm.addr(9); // change benefactor to allow a new safe
        safe = deploySafeProxy(1); // re-deploy safe expecting single deposit
        submitPendingDeposits(1);
        executePendingDeposits(1, 1 ether);
    }

    // - funder executes deposit after submit multiple deposit
    function test_execute_deposits_funder_after_submit_multiple() public {
        submitPendingDeposits(4);
        executePendingDeposits(4, 1 ether);
    }

    // - benefactor can resubmit deposits after reset
    function test_resubmit_deposits_after_reset() public {
        submitPendingDeposits(4);
        vm.prank(funder);
        deployer.clearPendingDeposits(benefactor);
        submitPendingDeposits(4);
        executePendingDeposits(4, 1 ether);
    }

    // Testing this contract on Gnosis chain with a deposit data created with 
    // the tool https://github.com/gnosischain/validator-data-generator
    // Test if the deposit is correct w.r.t. to this contract's logic
    function test_invalid_deposit_data_root() public {
        bytes memory pubkey =
            hex"8ec8542ad9f12d7e3c4ab35af1c005175244837bfb75125d1ea9669444f62911b430b35c6f1da9f732a1c07cb35b7e0b";
        bytes memory signature =
            hex"a0e2e422a220c15d99eba4675aebe4768ae846d2cb9b9ee8db5a19b8c20ee4c010bcfae099894cdf2d523b3a8fcb4d0e09a928125b5d9e43a80771d999d30137138364d7aff1c9bc38b6d59df8b6c08d3f85fc390e0d7f7f1f5d5b7f91feb702";
        bytes memory withdrawal_credentials = hex"0100000000000000000000009f755c84f51bfed22b98813db0b78b51e501dfeb";
        bytes32 expected_deposit_data_root = hex"adeb978612875a4f25312acff0d4d4ae5e87bb3677b6d052e874f0479eccd4ac";
        bytes32 expected_deposit_message_root = hex"3b8473c6904305c71a55252e131cb0730360e2005c367bdcc8b3aafb03acc308";
        uint256 stake_amount = 1 ether;
        bytes32 deposit_data_root = computeDataRoot(pubkey, withdrawal_credentials, signature, stake_amount);
        assertEq(deposit_data_root, expected_deposit_data_root);
        vm.expectRevert();
        assertEq(deposit_data_root, expected_deposit_message_root);
    }

    function isExpired(Safe safe) public returns (bool) {
        (uint256 expiry,,,,,) = safeModule.getUserInfo(safe);
        return block.timestamp >= expiry;
    }

    function mintAndWithdraw(Safe safe, uint256 amount) public {
        withdrawalToken.mint(address(safe), amount);
        safeModule.withdrawBalance(safe, false);
    }

    function enableAutoClaim() internal {
        vm.prank(benefactor);
        safeModule.setAutoClaim(safe, true);
    }

    function assertBalance(address to, uint256 amount) internal {
        assertEq(withdrawalToken.balanceOf(to), amount, "not expected balance");
    }

    function afterExpiry() internal {
        vm.warp(block.timestamp + expiryDuration + 1);
    }

    function executePendingDeposits(uint256 numDeposits, uint256 depositValue) internal {
        // Fund deployer for deposits
        withdrawalToken.mint(address(deployer), numDeposits * depositValue);
        vm.prank(funder);
        deployer.executePendingDeposits(benefactor);
    }

    function submitPendingDeposits(uint256 numDeposits) internal {
        bytes memory pubkeys;
        bytes memory signatures;
        bytes32[] memory deposit_data_roots = new bytes32[](numDeposits);

        for (uint256 i = 0; i < numDeposits; i++) {
            (bytes memory pubkey,, bytes memory signature, bytes32 deposit_data_root) =
                generateDepositData(address(safe), 1 ether);

            pubkeys = abi.encodePacked(pubkeys, pubkey);
            signatures = abi.encodePacked(signatures, signature);
            deposit_data_roots[i] = deposit_data_root;
        }

        vm.prank(benefactor);
        deployer.submitPendingDeposits(pubkeys, signatures, deposit_data_roots);
    }

    // Fill deposit data with format valid pubkey and signature (actual signature is invalid)
    function generateDepositData(address withdrawalAddress, uint256 stake_amount)
        internal
        returns (
            bytes memory pubkey,
            bytes memory withdrawal_credentials,
            bytes memory signature,
            bytes32 deposit_data_root
        )
    {
        bytes memory pubkey =
            hex"a42d9eb4891da533237d7bb496138bba2b24221fda3b9f39762583e75ad484bf1e618ed48a2bae997fe4ccd685794b80";
        bytes memory signature =
            hex"a3b59b76906764d6326903e0284be5517e8bd12eecd2062af0abc05ce0834ec75e42401909659f8d143ac0a7ded4eb3114d0469c639df20a3362a6be9179250fc222c0f420c4d831a532672a7259c64cfd3438aa3c0337f32df6be81b834ea34";
        bytes memory withdrawal_credentials = addressTo0x1WithdrawalCredentials(withdrawalAddress);
        bytes32 deposit_data_root = computeDataRoot(pubkey, withdrawal_credentials, signature, stake_amount);
        return (pubkey, withdrawal_credentials, signature, deposit_data_root);
    }

    // Copied from https://github.com/gnosischain/deposit-contract/blob/5da337d6384f743a47de7c06df2b7efe481ce190/contracts/SBCDepositContract.sol#L161
    function computeDataRoot(
        bytes memory pubkey,
        bytes memory withdrawal_credentials,
        bytes memory signature,
        uint256 stake_amount
    ) internal returns (bytes32) {
        // Multiply stake amount by 32 (1 GNO for validating instead of the 32 ETH expected)
        stake_amount = 32 * stake_amount;
        uint256 deposit_amount = stake_amount / 1 gwei;
        bytes memory amount = to_little_endian_64(uint64(deposit_amount));

        // Compute deposit data root (`DepositData` hash tree root)
        bytes32 pubkey_root = sha256(abi.encodePacked(pubkey, bytes16(0)));
        bytes32[3] memory sig_parts = abi.decode(signature, (bytes32[3]));
        bytes32 signature_root = sha256(
            abi.encodePacked(
                sha256(abi.encodePacked(sig_parts[0], sig_parts[1])), sha256(abi.encodePacked(sig_parts[2], bytes32(0)))
            )
        );
        return sha256(
            abi.encodePacked(
                sha256(abi.encodePacked(pubkey_root, withdrawal_credentials)),
                sha256(abi.encodePacked(amount, bytes24(0), signature_root))
            )
        );
    }

    function addressTo0x1WithdrawalCredentials(address addr) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(1), bytes3(0), bytes8(0), address(addr));
    }

    // Copied from https://github.com/gnosischain/deposit-contract/blob/5da337d6384f743a47de7c06df2b7efe481ce190/contracts/SBCDepositContract.sol#L161
    function to_little_endian_64(uint64 value) internal pure returns (bytes memory ret) {
        ret = new bytes(8);
        bytes8 bytesValue = bytes8(value);
        // Byteswapping during copying to bytes.
        ret[0] = bytesValue[7];
        ret[1] = bytesValue[6];
        ret[2] = bytesValue[5];
        ret[3] = bytesValue[4];
        ret[4] = bytesValue[3];
        ret[5] = bytesValue[2];
        ret[6] = bytesValue[1];
        ret[7] = bytesValue[0];
    }
}
