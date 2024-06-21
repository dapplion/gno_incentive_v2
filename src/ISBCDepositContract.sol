// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.13;

// Based on https://github.com/gnosischain/deposit-contract/blob/master/contracts/SBCDepositContract.sol
interface ISBCDepositContract {
    function batchDeposit(
        bytes calldata pubkeys,
        bytes calldata withdrawal_credentials,
        bytes calldata signatures,
        bytes32[] calldata deposit_data_roots
    ) external;
}
