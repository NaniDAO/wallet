// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

contract Wallet {
    address constant entryPoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    bytes32 immutable user;

    constructor(bytes32 _user) payable {
        user = _user;
    }

    function execute(address to, uint val, bytes calldata data) public payable {
        bytes32 usr = user; // Place immutable `user` onto stack.
        assembly ("memory-safe") {
            // Only the `user` or `entryPoint` have auth for executing wallet operations.
            if iszero(or(eq(caller(), usr), eq(caller(), entryPoint))) { revert(codesize(), 0x00) }
            calldatacopy(0x00, data.offset, data.length) // Copy call `data` to memory.
            // If `val` is not set to max uint256, perform call operation.
            if xor(val, not(0)) {
                pop(call(gas(), to, val, 0x00, data.length, codesize(), 0x00))
                returndatacopy(0x00, 0x00, returndatasize())
                return(0x00, returndatasize())
            }
            // Otherwise, delegate the call `data` operation for `to`.
            pop(delegatecall(gas(), to, 0x00, data.length, codesize(), 0x00))
            returndatacopy(0x00, 0x00, returndatasize())
            return(0x00, returndatasize())
        }
    }

    function validateUserOp(UserOperation calldata, bytes32 userOpHash, uint missingAccountFunds)
        public
        payable
        returns (uint validationData)
    {
        bytes32 usr = user; // Place immutable `user` onto stack.
        assembly ("memory-safe") {
            let m := mload(0x40) // Cache free memory pointer.
            if xor(caller(), entryPoint) { revert(codesize(), 0x00) } // Check `entryPoint` auth.
            // If `nonce` exceeds 64 bytes, extract signature aggregator as `validationData`.
            // Since hashed value must be signed by user, it is trusted to validate user ops.
            if gt(calldataload(0x84), 0xffffffffffffffff) {
                userOpHash := shr(64, calldataload(0x84))
                validationData := userOpHash
            }
            // ERC191 signed data is not supported by EVM, so `userOpHash` prep is manual.
            mstore(0x20, userOpHash) // Store into scratch space for keccak256.
            mstore(0x00, '\x00\x00\x00\x00\x19Ethereum Signed Message:\n32') // 28 bytes.
            mstore(0x00, keccak256(0x04, 0x3c)) // `32 * 2 - (32 - 28) = 60 = 0x3c`.
            calldatacopy(0x20, sub(calldatasize(), 0x60), 0x60) // Copy `v, r, s`.
            if xor(usr, mload(staticcall(gas(), 0x01, 0x00, 0x80, 0x01, 0x20))) {
                validationData := 1 // If ecrecover fails, `validationData` is 1.
            }
            // Refund `entryPoint` validation if required.
            if missingAccountFunds {
                pop(call(gas(), caller(), missingAccountFunds, codesize(), 0x00, codesize(), 0x00))
            }
            mstore(0x40, m) // Restore free memory pointer.
        }
    }

    function isValidSignature(bytes32 hash, bytes calldata signature)
        public
        payable
        returns (bytes4 magicValue)
    {
        bytes32 usr = user; // Place immutable `user` onto stack.
        assembly ("memory-safe") {
            // ERC191 signed data is not supported by EVM, so `hash` prep is manual.
            mstore(0x20, hash) // Store into scratch space for keccak256.
            mstore(0x00, '\x00\x00\x00\x00\x19Ethereum Signed Message:\n32') // 28 bytes.
            mstore(0x00, keccak256(0x04, 0x3c)) // `32 * 2 - (32 - 28) = 60 = 0x3c`.
            calldatacopy(0x20, signature.offset, signature.length) // Copy `v, r, s`.
            // If ecrecover succeeds, return ERC1271 magic value `0x1626ba7e`.
            if eq(usr, mload(staticcall(gas(), 0x01, 0x00, 0x80, 0x01, 0x20))) {
                magicValue := 0x1626ba7e
            }
        }
    }

    fallback() external payable {
        assembly ("memory-safe") {
            // If `msg.value` is set, `receive()`.
            if callvalue() { return(0x00, 0x00) }
            // Or, return `msg.sig` for safe tokens.
            mstore(0x20, shr(224, calldataload(0)))
            return(0x3C, 0x20)
        }
    }

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
}
