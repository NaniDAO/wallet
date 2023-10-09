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
            if lt(val, 900000000000000000000000000000000000000000000000000) {
                pop(call(gas(), to, val, 0x00, data.length, 0x00, 0x00))
                returndatacopy(0x00, 0x00, returndatasize())
                return(0x00, returndatasize())
            }
            pop(delegatecall(gas(), to, 0x00, data.length, 0x00, 0x00))
            returndatacopy(0x00, 0x00, returndatasize())
            return(0x00, returndatasize())
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

    function validateUserOp(UserOperation calldata, bytes32 userOpHash, uint missingAccountFunds)
        public
        payable
        returns (uint validationData)
    {
        bytes32 usr = user;
        assembly ("memory-safe") {
            if xor(caller(), entryPoint) { revert(0x00, 0x00) }
            let m := mload(0x40)
            if calldataload(0x84) { userOpHash := calldataload(0x208) }
            mstore(0x20, userOpHash) // Store into scratch space for keccak256.
            mstore(0x00, '\x00\x00\x00\x00\x19Ethereum Signed Message:\n32') // 28 bytes.
            mstore(0x00, keccak256(0x04, 0x3c)) // `32 * 2 - (32 - 28) = 60 = 0x3c`.
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
