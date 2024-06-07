// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract EIP4788Mock {
    bytes32 private beaconStateRoot;

    // Emulate selector-less call from https://eips.ethereum.org/EIPS/eip-4788 pseudocode
    fallback(bytes calldata) external payable returns (bytes memory) {
        return abi.encodePacked(beaconStateRoot);
    }

    // Anyone can set the address
    function set(bytes32 _root) public {
        beaconStateRoot = _root;
    }
}
