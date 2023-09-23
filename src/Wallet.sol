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
            if xor(caller(), entryPoint) { revert(0x00, 0x00) }
            let dataMem := mload(data.offset)
            if iszero(op) {
                let success := call(gas(), to, val, add(dataMem, 0x20), mload(dataMem), gas(), 0x00)
                returndatacopy(0x00, 0x00, returndatasize())
                if iszero(success) { revert(0x00, returndatasize()) }
                return(0x00, returndatasize())
            }
            let success := delegatecall(gas(), to, add(dataMem, 0x20), mload(dataMem), gas(), 0x00)
            returndatacopy(0x00, 0x00, returndatasize())
            if iszero(success) { revert(0x00, returndatasize()) }
            return(0x00, returndatasize())
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
            if xor(caller(), entryPoint) { revert(0x00, 0x00) }
        }

        validationData = _isValidSignature(userOpHash, userOp.signature);

        if (missingAccountFunds != 0) {
            assembly ("memory-safe") {
                pop(call(gas(), caller(), missingAccountFunds, 0x00, 0x00, 0x00, 0x00))
            }
        }
    }

    // (solady/blob/main/src/utils/ECDSA.sol)
    // Edited to return uint for eip-4337 validation.
    function _isValidSignature(bytes32 hash, bytes calldata signature)
        internal
        view
        returns (uint isValid)
    {
        bytes32 _owner = owner;
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(0x00, hash) // Store hash at memory slot 0x00.
            // Extract 'v' from signature and store at memory slot 0x20.
            mstore(0x20, byte(0, calldataload(add(signature.offset, 0x40))))
            // Copy 'r' and 's' from signature to memory starting at slot 0x40.
            calldatacopy(0x40, signature.offset, 0x40)
            // Perform ECDSA recovery; XOR with _owner. Store result in isValid (0 if valid, 1 if not).
            isValid := xor(_owner, mload(staticcall(gas(), 1, 0x00, 0x80, 0x01, 0x20)))
            mstore(0x40, m) // Restore the free memory pointer.
            // If ECDSA check failed (isValid is 1), proceed with contract-based check.
            if isValid {
                let f := shl(224, 0x1626ba7e)
                mstore(m, f) // `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
                mstore(add(m, 0x04), hash)
                let d := add(m, 0x24)
                mstore(d, 0x40) // The offset of the `signature` in the calldata.
                mstore(add(m, 0x44), signature.length)
                // Copy the `signature` over.
                calldatacopy(add(m, 0x64), signature.offset, signature.length)
                // Perform staticcall for contract-based check; update isValid (0 if valid, 1 if not).
                isValid :=
                    iszero(eq(staticcall(gas(), _owner, m, add(signature.length, 0x64), d, 0x20), f))
            }
        }
    }

    // Receivers...
    receive() external payable {}

    fallback() external payable {
        assembly ("memory-safe") {
            let s := shr(224, calldataload(0))
            // `onERC721Received`.
            if eq(s, 0x150b7a02) {
                mstore(0x20, s)
                return(0x3c, 0x20)
            }
            // `onERC1155Received`.
            if eq(s, 0xf23a6e61) {
                mstore(0x20, s)
                return(0x3c, 0x20)
            }
            // `onERC1155BatchReceived`.
            if eq(s, 0xbc197c81) {
                mstore(0x20, s)
                return(0x3c, 0x20)
            }
        }
    }
}
