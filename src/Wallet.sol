// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

contract Wallet {
    address constant entryPoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    bytes32 immutable owner;

    // todo: can we make owner constant since salt?

    constructor(bytes32 _owner) payable {
        owner = _owner;
    }

    // Execute Op...
    function execute(address to, uint256 val, bytes calldata data, bool del) public payable {
        assembly {
            if iszero(eq(caller(), entryPoint)) { revert(0, 0) }
            let dataMem := mload(data.offset)
            if iszero(del) {
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
        uint256 nonce;
        bytes initCode;
        bytes callData;
        uint256 callGasLimit;
        uint256 verificationGasLimit;
        uint256 preVerificationGas;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
        bytes paymasterAndData;
        bytes signature;
    }

    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        public
        payable
        returns (uint256 validationData)
    {
        assembly ("memory-safe") {
            if iszero(eq(caller(), entryPoint)) { revert(0, 0) }
        }

        // ToDo: add nonce switch
        validationData = _isValidSignature(userOpHash, userOp.signature);

        if (missingAccountFunds != 0) {
            assembly ("memory-safe") {
                pop(call(gas(), caller(), missingAccountFunds, 0x00, 0x00, 0x00, 0x00))
            }
        }
    }

    // todo: do we want eip1271

    // (solady/blob/main/src/utils/ECDSA.sol)
    // Edited to return uint256 for eip-4337 validation.
    function _isValidSignature(bytes32 hash, bytes calldata signature) internal view returns (uint256 flag) {
        bytes32 _owner = owner;
        assembly ("memory-safe") {
            let m := mload(0x40) // Cache the free memory pointer.
            mstore(0x00, hash)
            mstore(0x20, byte(0, calldataload(add(signature.offset, 0x40)))) // `v`.
            calldatacopy(0x40, signature.offset, 0x40) // Copy `r` and `s`.
            let result :=
                mload(
                    staticcall(
                        gas(), // Amount of gas left for the transaction.
                        eq(signature.length, 65), // Address of `ecrecover`.
                        0x00, // Start of input.
                        0x80, // Size of input.
                        0x01, // Start of output.
                        0x20 // Size of output.
                    )
                )
            // `returndatasize()` will be `0x20` upon success, and `0x00` otherwise.
            if iszero(returndatasize()) { flag := 1 }
            if iszero(eq(_owner, result)) { flag := 1 }
            mstore(0x60, 0) // Restore the zero slot.
            mstore(0x40, m) // Restore the free memory pointer.

            if eq(flag, 1) {
                let f := shl(224, 0x1626ba7e)
                mstore(m, f) // `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
                mstore(add(m, 0x04), hash)
                let d := add(m, 0x24)
                mstore(d, 0x40) // The offset of the `signature` in the calldata.
                mstore(add(m, 0x44), signature.length)
                // Copy the `signature` over.
                calldatacopy(add(m, 0x64), signature.offset, signature.length)
                // forgefmt: disable-next-item
                flag := iszero(and(
                    // Whether the returndata is the magic value `0x1626ba7e` (left-aligned).
                    eq(mload(d), f),
                    // Whether the staticcall does not revert.
                    // This must be placed at the end of the `and` clause,
                    // as the arguments are evaluated from right to left.
                    staticcall(
                        gas(), // Remaining gas.
                        _owner, // The `owner` address.
                        m, // Offset of calldata in memory.
                        add(signature.length, 0x64), // Length of calldata in memory.
                        d, // Offset of returndata.
                        0x20 // Length of returndata to write.
                    )
                ))
            }
        }
    }

    // Receivers...
    receive() external payable {}

    fallback() external payable {
        assembly ("memory-safe") {
            let s := shr(224, calldataload(0))
            // `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`.
            if eq(s, 0x150b7a02) {
                mstore(0x20, s)
                return(0x3c, 0x20)
            }
            // `bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes))")`.
            if eq(s, 0xf23a6e61) {
                mstore(0x20, s)
                return(0x3c, 0x20)
            }
            // `bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes))"`.
            if eq(s, 0xbc197c81) {
                mstore(0x20, s)
                return(0x3c, 0x20)
            }
        }
    }
}
