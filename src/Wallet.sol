// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

contract Wallet {
    address constant entryPoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    bytes32 immutable user;

    constructor(bytes32 _user) payable {
        user = _user;
    }

    /// @dev Permissioned call execution logic. Returns data.
    function execute(address to, uint val, bytes calldata data) public payable {
        bytes32 usr = user;
        assembly ("memory-safe") {
            if and(xor(caller(), usr), xor(caller(), entryPoint)) { revert(0x00, 0x00) }
            calldatacopy(0x00, data.offset, data.length)
            if call(gas(), to, val, 0x00, data.length, 0x00, 0x00) {
                returndatacopy(0x00, 0x00, returndatasize())
                return(0x00, returndatasize())
            }
            revert(0x00, returndatasize())
        }
    }

    /// @dev Permissioned delegatecall execution logic. Returns data.
    function execute(address to, bytes calldata data) public payable {
        bytes32 usr = user;
        assembly ("memory-safe") {
            if and(xor(caller(), usr), xor(caller(), entryPoint)) { revert(0x00, 0x00) }
            calldatacopy(0x00, data.offset, data.length)
            if delegatecall(gas(), to, 0x00, data.length, 0x00, 0x00) {
                returndatacopy(0x00, 0x00, returndatasize())
                return(0x00, returndatasize())
            }
            revert(0x00, returndatasize())
        }
    }

    /// @dev ERC1271 contract signature validation logic. Returns magic value.
    function isValidSignature(bytes32 hash, bytes calldata signature) public view {
        bytes32 usr = user;
        assembly ("memory-safe") {
            mstore(0x00, hash) // Place `hash` into first slot.
            // Assume the `signature` is encoded as `v + r + s`.
            calldatacopy(0x20, signature.offset, signature.length)
            // If the return data matches `user` return ERC1271 magic value.
            if eq(usr, mload(staticcall(gas(), 0x01, 0x00, 0x80, 0x01, 0x20))) {
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
        uint missingAccountFunds
    ) public payable returns (uint validationData) {
        // Memo `sig` calldata item from struct.
        bytes calldata sig = userOp.signature;
        bytes32 usr = user; // Pull `user` onto stack.
        assembly ("memory-safe") {
            // Only `entryPoint` may call this function.
            if xor(caller(), entryPoint) { revert(0x00, 0x00) }
            let m := mload(0x40) // Cache the free memory pointer.
            mstore(0x00, userOpHash) // Place `userOpHash` into first slot.
            // Assume the `signature` is encoded as `v + r + s`.
            calldatacopy(0x20, sig.offset, sig.length)
            // If ecrecover doesn't match `user`, `validationData` is `1`, else `0`.
            if xor(usr, mload(staticcall(gas(), 0x01, 0x00, 0x80, 0x01, 0x20))) {
                validationData := 1
            }
            mstore(0x40, m) // Restore the free memory pointer.
            // Refund the `entryPoint` if any relayer gas is owed.
            pop(call(gas(), caller(), missingAccountFunds, 0x00, 0x00, 0x00, 0x00))
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
