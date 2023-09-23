// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

contract Wallet {
    bytes32 immutable owner;
    address constant entryPoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    constructor(bytes32 _owner) payable {
        owner = _owner;
    }

    // Execute Op...
    function execute(bytes32 to, uint val, bytes calldata data, uint op) public payable {
        assembly {
            if xor(caller(), entryPoint) { revert(0, 0) }
            let dataMem := mload(data.offset)
            if iszero(op) {
                let success := call(gas(), to, val, add(dataMem, 32), mload(dataMem), gas(), 0)
                returndatacopy(0, 0, returndatasize())
                if iszero(success) { revert(0, returndatasize()) }
                return(0, returndatasize())
            }
            let success := delegatecall(gas(), to, add(dataMem, 32), mload(dataMem), gas(), 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(success) { revert(0, returndatasize()) }
            return(0, returndatasize())
        }
    }

    // eip-1271...
    function isValidSignature(bytes32 hash, bytes calldata sig) public view returns (bytes4 y) {
        if (_isValidSignature(hash, sig) == 0) y = this.isValidSignature.selector;
    }

    // eip-4337...
    struct UserOperation {
        address sender;
        uint nonce;
        bytes initCode;
        bytes callData;
        uint callGasLimit;
        uint verificationGasLimit;
        uint preVerificationGas;
        uint maxFeePerGas;
        uint maxPriorityFeePerGas;
        bytes paymasterAndData;
        bytes signature;
    }

    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint missingAccountFunds
    ) public payable returns (uint validationData) {
        assembly ("memory-safe") {
            if xor(caller(), entryPoint) { revert(0, 0) }
        }

        validationData = _isValidSignature(userOpHash, userOp.signature);

        if (missingAccountFunds != 0) {
            assembly ("memory-safe") {
                pop(call(gas(), caller(), missingAccountFunds, 0, 0, 0, 0))
            }
        }
    }

    function _isValidSignature(bytes32 hash, bytes calldata signature)
        internal
        view
        returns (uint isValid)
    {
        bytes32 o = owner;
        assembly ("memory-safe") {
            let m := mload(64)
            mstore(0, hash)
            mstore(32, byte(0, calldataload(add(signature.offset, 64))))
            calldatacopy(64, signature.offset, 64)
            isValid := xor(o, mload(staticcall(gas(), 1, 0, 128, 1, 32)))
            mstore(64, m)
        }
    }

    // Receivers...
    receive() external payable {}

    fallback() external payable {
        assembly ("memory-safe") {
            let s := shr(224, calldataload(0))
            if eq(s, 0x150b7a02) {
                mstore(32, s)
                return(60, 32)
            }
            if eq(s, 0xf23a6e61) {
                mstore(32, s)
                return(60, 32)
            }
            if eq(s, 0xbc197c81) {
                mstore(32, s)
                return(60, 32)
            }
        }
    }
}
