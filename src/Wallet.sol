// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

contract Wallet {
    address constant entryPoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    bytes32 immutable owner;

    constructor(bytes32 _owner) payable {
        owner = _owner;
    }

    /// @dev Permissioned call or delegatecall logic. Reverts zeroed. Returns data digest.
    function execute(bytes32 to, uint val, bytes calldata data, uint op) public payable {
        bytes32 o = owner;
        assembly ("memory-safe") {
            // Only `owner` or `entryPoint` can execute Wallet `op`.
            if and(xor(caller(), o), xor(caller(), entryPoint)) { revert(0, 0) }
            calldatacopy(0, data.offset, data.length)
            if op {
                if iszero(call(gas(), to, val, 0, data.length, 0, 0)) { revert(0, 0) }
                returndatacopy(0, 0, returndatasize())
                return(0, returndatasize())
            } // If no `op` input use delegatecall.
            if iszero(delegatecall(gas(), to, 0, data.length, 0, 0)) { revert(0, 0) }
            returndatacopy(0, 0, returndatasize())
            return(0, returndatasize())
        }
    }

    /// @dev ERC1271 contract signature validation logic. Returns magic value.
    function isValidSignature(bytes32 hash, bytes calldata sig) public payable {
        bytes32 o = owner;
        assembly ("memory-safe") {
            mstore(0, hash) // Load `hash` into first slot.
            // Load `v` as 65th byte in `sig` by adding 64 to offset.
            mstore(0x20, byte(0, calldataload(add(sig.offset, 0x40))))
            // Load `r` and `s` in `sig` as 64 bytes from offset.
            calldatacopy(0x40, sig.offset, 0x40)
            // If return data matches `owner` return EIP-1271 magic value.
            if eq(o, mload(staticcall(gas(), 1, 0, 0x80, 0x01, 0x20))) {
                mstore(0x00, 0x1626ba7e) // Store magic value.
                return(0x1C, 0x04) // Return magic value.
            }
        }
    }

    /// @dev ERC4337 struct.
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

    /// @dev ERC4337 account.
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint // Prefunded.
    ) public payable returns (uint validationData) {
        // Memo `sig` calldata item from struct.
        bytes calldata sig = userOp.signature;
        bytes32 o = owner; // Pull `owner` onto stack.
        assembly ("memory-safe") {
            // Only `entryPoint` may call this function.
            if xor(caller(), entryPoint) { revert(0, 0) }
            let m := mload(0x40) // Cache free memory pointer.
            mstore(0, userOpHash) // Memo `userOpHash` into first slot.
            // Memo `v` as 65th byte in `sig` by adding 64 to offset.
            mstore(0x20, byte(0, calldataload(add(sig.offset, 0x40))))
            // Memo `r` and `s` in `sig` as 64 bytes from offset.
            calldatacopy(0x40, sig.offset, 0x40)
            // If return data matches `owner` magic value of `0` is default. Else, `1`.
            // This is what the `entryPoint` expects under eip-4337 though unintuitive.
            if xor(o, mload(staticcall(gas(), 1, 0, 0x80, 0x01, 0x20))) { validationData := 1 }
            mstore(0x40, m) // Restore the free memory pointer.
        }
    }

    /// @dev Ether (ETH) receiver.
    receive() external payable {}

    /// @dev Callback handling.
    fallback() external payable {
        assembly ("memory-safe") {
            // Shift unknown call into its `msg.sig`.
            mstore(0x20, shr(224, calldataload(0)))
            return(0x3C, 0x20) // Return `msg.sig`.
        }
    }
}
