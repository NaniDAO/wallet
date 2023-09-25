// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

contract Wallet {
    bytes32 immutable owner;
    address constant entryPoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    constructor(bytes32 _owner) payable {
        owner = _owner;
    }

    // Execute Op...
    function execute(bytes32 to, bytes calldata data) public payable {
        bytes32 o = owner;
        assembly {
            if and(xor(caller(), entryPoint), xor(caller(), o)) { revert(0, 0) }

            calldatacopy(0, data.offset, data.length)

            let success := delegatecall(gas(), to, 0, data.length, gas(), 0)
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
        assembly {
            mstore(32, shr(224, calldataload(0)))
            return(60, 32)
        }
    }
}
