// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

contract Wallet {
    address constant entryPoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    bytes32 immutable owner;

    constructor(bytes32 _owner) payable {
        owner = _owner;
    }

    // Execute Op...
    function execute(bytes32 to, uint val, bytes calldata data, uint op) public payable {
        // Load `owner`.
        bytes32 o = owner;
        assembly ("memory-safe") {
            // Only `owner` or `entryPoint` may call this function.
            if and(xor(caller(), o), xor(caller(), entryPoint)) { revert(0, 0) }
            // Copy `data` to memory.
            calldatacopy(0, data.offset, data.length)
            // If any non-zero `op` we use call(). This is done as optimization.
            if op {
                // call() and load `success` state.
                let success := call(gas(), to, val, 0, data.length, 0, 0)
                // Copy returned data to memory.
                returndatacopy(0, 0, returndatasize())
                // If call() failed, revert with return data.
                if iszero(success) { revert(0, returndatasize()) }
                // Otherwise, return data.
                return(0, returndatasize())
            }
            // If zero `op`, perform delegatecall().
            let success := delegatecall(gas(), to, 0, data.length, 0, 0)
            // Copy returned data to memory.
            returndatacopy(0, 0, returndatasize())
            // If delegatecall() failed, revert with return data.
            if iszero(success) { revert(0, returndatasize()) }
            // Otherwise, return data.
            return(0, returndatasize())
        }
    }

    // eip-1271...
    // audit-note: we assume low-level calls and thus don't bother with view.
    function isValidSignature(bytes32 hash, bytes calldata sig) public payable {
        // Load `owner`.
        bytes32 o = owner;
        assembly ("memory-safe") {
            // Load free memory pointer.
            let m := mload(0x40)
            // Load `hash` into first slot.
            mstore(0, hash)
            // Load `v` as 65th byte in `sig` by adding 64 to offset.
            mstore(0x20, byte(0, calldataload(add(sig.offset, 0x40))))
            // Load `r` and `s` in `sig` as 64 bytes from offset.
            calldatacopy(0x40, sig.offset, 0x40)
            // If the returned data matches `owner` return magic value.
            if eq(o, mload(staticcall(gas(), 1, 0, 0x80, 0x01, 0x20))) {
                mstore(0x40, m) // Restore the free memory pointer.
                mstore(0x20, 0x1626ba7e) // Store magic value.
                return(0x3C, 0x20) // Return magic value.
            }
            // Restore the free memory pointer.
            mstore(0x40, m)
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
        // Fetch `sig` item from struct.
        bytes calldata sig = userOp.signature;
        // Load `owner`.
        bytes32 o = owner;
        assembly ("memory-safe") {
            // Only `entryPoint` may call this function.
            if xor(caller(), entryPoint) { revert(0, 0) }
            // Load free memory pointer.
            let m := mload(0x40)
            // Load `userOpHash` into first slot.
            mstore(0, userOpHash)
            // Load `v` as 65th byte in `sig` by adding 64 to offset.
            mstore(0x20, byte(0, calldataload(add(sig.offset, 0x40))))
            // Load `r` and `s` in `sig` as 64 bytes from offset.
            calldatacopy(0x40, sig.offset, 0x40)
            // If the returned data matches `owner` return magic value of `0`. Else, `1`.
            // This is what the `entryPoint` expects under eip-4337 though unintuitive.
            validationData := xor(o, mload(staticcall(gas(), 1, 0, 0x80, 0x01, 0x20)))
            // Restore the free memory pointer.
            mstore(0x40, m)
        }
    }

    // Receivers...
    receive() external payable {}

    // audit-note: This is for `safeTransfer`-type
    // receiver compatibility. Since only `msg.sig`
    // can be returned, risk seems low. Other checks
    // are punted onto the calling contracts.
    fallback() external payable {
        assembly {
            // Shift any unexpected call to `msg.sig`
            mstore(0x20, shr(224, calldataload(0)))
            // Return `msg.sig`.
            return(0x3C, 0x20)
        }
    }
}
