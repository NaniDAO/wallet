// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

contract Wallet {
    address constant entryPoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    bytes32 immutable owner;

    constructor(bytes32 _owner) payable {
        owner = _owner;
    }

    // Execute Op...
    function execute(bytes32 to, bytes calldata data) public payable {
        assembly {
            if xor(caller(), entryPoint) { revert(0, 0) }
            calldatacopy(0, data.offset, data.length)
            let success := delegatecall(gas(), to, 0, data.length, 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(success) { revert(0, returndatasize()) }
            return(0, returndatasize())
        }
    }

    // eip-1271...
    function isValidSignature(bytes32 hash, bytes calldata sig) public payable {
        bytes32 o = owner;
        assembly {
            let m := mload(64)
            mstore(0, hash)
            mstore(32, 28)
            calldatacopy(64, sig.offset, 64)
            if eq(o, mload(staticcall(gas(), 1, 0, 128, 1, 32))) {
                mstore(64, m)
                mstore(32, 0x1626ba7e)
                return(60, 32)
            }
            mstore(64, m)
        }
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
        uint // Prefunded.
    ) public payable returns (uint validationData) {
        bytes calldata sig = userOp.signature;
        bytes32 o = owner;
        assembly ("memory-safe") {
            if xor(caller(), entryPoint) { revert(0, 0) }
            let m := mload(64)
            mstore(0, userOpHash)
            mstore(32, 28)
            calldatacopy(64, sig.offset, 64)
            validationData := xor(o, mload(staticcall(gas(), 1, 0, 128, 1, 32)))
            mstore(64, m)
        }
    }

    // Receivers...
    receive() external payable {}

    fallback() external payable {
        assembly {
            mstore(32, shr(224, calldataload(0)))
            return(60, 32)
        }
    }
}
