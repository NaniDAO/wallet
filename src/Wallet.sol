// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

contract Wallet {
    address constant entryPoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    bytes32 immutable user;

    constructor(bytes32 _user) payable {
        user = _user;
    }

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

    function isValidSignature(bytes32 hash, bytes calldata signature) public view {
        bytes32 usr = user;
        assembly ("memory-safe") {
            mstore(0x00, hash)
            calldatacopy(0x20, signature.offset, signature.length)
            if eq(usr, mload(staticcall(gas(), 0x01, 0x00, 0x80, 0x01, 0x20))) {
                mstore(0x00, 0x1626ba7e)
                return(0x1C, 0x04)
            }
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

    // 0. 4 bytes - function sig
    // 1. 32 bytes - userOp offset
    // 2. 32 bytes - userOpHash
    // 3. 32 bytes - missingAccountFunds
    // 4. 32 bytes - sender
    // 5. 32 bytes - nonce
    // 6. 32 bytes - initCode offset
    // 7. 32 bytes - callData offset
    // 8. 32 bytes - callGasLimit
    // 9. 32 bytes - verificationGasLimit
    // 10. 32 bytes - preVerificationGas
    // 11. 32 bytes - maxFeePerGas
    // 12. 32 bytes - maxPriorityFeePerGas
    // 13. 32 bytes - paymasterAndData offset
    // 14. 32 bytes - signature offset
    // 15. 32 bytes - initCode length
    // 16. [initCode length] bytes - initCode
    // 17. 32 bytes - callData length
    // 18. [callData length] bytes - callData
    // 19. 32 bytes - paymasterAndData length
    // 20. [signature length] bytes - paymasterAndData
    // 21. 32 bytes - signature length
    // 22. [signature length] bytes - signature

    function validateUserOp(UserOperation calldata, bytes32 userOpHash, uint missingAccountFunds)
        public
        payable
        returns (uint validationData)
    {
        bytes32 usr = user;
        assembly ("memory-safe") {
            if xor(caller(), entryPoint) { revert(0x00, 0x00) }
            let m := mload(0x40)
            if calldataload(0x84) {
                userOpHash := shr(96, calldataload(0x84))
                if xor(userOpHash, calldataload(add(calldataload(0xe0), 0x24))) {
                    validationData := 1
                }
            }
            mstore(0x00, userOpHash)
            calldatacopy(0x20, sub(calldatasize(), 0x60), 0x60)
            if xor(usr, mload(staticcall(gas(), 0x01, 0x00, 0x80, 0x01, 0x20))) {
                validationData := 1
            }
            mstore(0x40, m)
            if missingAccountFunds {
                pop(call(gas(), caller(), missingAccountFunds, 0x00, 0x00, 0x00, 0x00))
            }
        }
    }

    fallback() external payable {
        assembly ("memory-safe") {
            if callvalue() { return(0x00, 0x00) }
            mstore(0x20, shr(224, calldataload(0)))
            return(0x3C, 0x20)
        }
    }
}
