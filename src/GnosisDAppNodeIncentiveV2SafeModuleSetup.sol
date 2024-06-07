// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "safe-smart-account/contracts/Safe.sol";
import "./GnosisDAppNodeIncentiveV2SafeModule.sol";

/**
 * @title SafeModuleSetup - A utility contract for setting up a Safe with modules.
 * @dev The Safe `setup` function accepts `to` and `data` parameters for a delegate call during initialization. This
 *      contract can be specified as the `to` with `data` ABI encoding the `enableModules` call so that a Safe is
 *      created with the specified modules. In particular, this allows a ERC-4337 compatible Safe to be created as part
 *      of a ERC-4337 user operation with the `Safe4337Module` enabled right away.
 * @custom:security-contact bounty@safe.global
 */
contract GnosisDAppNodeIncentiveV2SafeModuleSetup {
    /**
     * @notice Enable the specified Safe modules.
     * @dev This call will only work if used from a Safe via delegatecall. It is intended to be used as part of the
     *      Safe `setup`, allowing Safes to be created with an initial set of enabled modules.
     */
    function setupModule(
        address safeModule,
        uint256 expiry,
        uint256 withdrawThreshold,
        address benefactor,
        address funder,
        bytes32[] calldata pubkeyHashes
    ) external {
        Safe(payable(address(this))).enableModule(safeModule);
        GnosisDAppNodeIncentiveV2SafeModule(safeModule).registerSafe(
            expiry, withdrawThreshold, benefactor, funder, pubkeyHashes
        );
    }
}
