// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

contract Wallet {
    address constant entryPoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    address immutable owner;

    constructor() payable {
        bytes32 hash = keccak256(
            abi.encodePacked(bytes1(0xff), msg.sender, keccak256(abi.encodePacked(address(this))), keccak256(msg.data))
        );

        owner = address(uint160(uint256(hash)));
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
    function isValidSignature(bytes32 hash, bytes calldata sig) public view returns (uint32) {
        return isValidSignatureNowCalldata(owner, hash, sig) ? 0x1626ba7e : 0xffffffff;
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

        validationData = isValidSignatureNowCalldata(owner, userOpHash, userOp.signature) ? 0 : 1;

        if (missingAccountFunds != 0) {
            assembly ("memory-safe") {
                pop(call(gas(), caller(), missingAccountFunds, 0x00, 0x00, 0x00, 0x00))
            }
        }
    }

    // Receivers...
    receive() external payable {}

    fallback() external payable {
        assembly {
            // Shift right by 224 bits to get the function signature.
            let shiftedSig := shr(224, calldataload(0))

            // `keccak256("onERC721Received(address,address,uint256,bytes)")`.
            if eq(shiftedSig, 0x150b7a02) {
                mstore(0x00, shl(224, shiftedSig))
                return(0x00, 0x20)
            }

            // `keccak256("onERC1155Received(address,address,uint256,uint256,bytes)")`.
            if eq(shiftedSig, 0xf23a6e61) {
                mstore(0x00, shl(224, shiftedSig))
                return(0x00, 0x20)
            }

            // `keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"`.
            if eq(shiftedSig, 0xbc197c81) {
                mstore(0x00, shl(224, shiftedSig))
                return(0x00, 0x20)
            }
        }
    }
}

// (solady/blob/main/src/utils/SignatureCheckerLib.sol)
function isValidSignatureNowCalldata(address signer, bytes32 hash, bytes calldata signature)
    view
    returns (bool isValid)
{
    assembly ("memory-safe") {
        // Clean the upper 96 bits of `signer` in case they are dirty.
        for { signer := shr(96, shl(96, signer)) } signer {} {
            let m := mload(0x40)
            if eq(signature.length, 65) {
                mstore(0x00, hash)
                mstore(0x20, byte(0, calldataload(add(signature.offset, 0x40)))) // `v`.
                calldatacopy(0x40, signature.offset, 0x40) // `r`, `s`.
                let t :=
                    staticcall(
                        gas(), // Amount of gas left for the transaction.
                        1, // Address of `ecrecover`.
                        0x00, // Start of input.
                        0x80, // Size of input.
                        0x01, // Start of output.
                        0x20 // Size of output.
                    )
                // `returndatasize()` will be `0x20` upon success, and `0x00` otherwise.
                if iszero(or(iszero(returndatasize()), xor(signer, mload(t)))) {
                    isValid := 1
                    mstore(0x60, 0) // Restore the zero slot.
                    mstore(0x40, m) // Restore the free memory pointer.
                    break
                }
            }
            mstore(0x60, 0) // Restore the zero slot.
            mstore(0x40, m) // Restore the free memory pointer.

            let f := shl(224, 0x1626ba7e)
            mstore(m, f) // `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
            mstore(add(m, 0x04), hash)
            let d := add(m, 0x24)
            mstore(d, 0x40) // The offset of the `signature` in the calldata.
            mstore(add(m, 0x44), signature.length)
            // Copy the `signature` over.
            calldatacopy(add(m, 0x64), signature.offset, signature.length)
            // forgefmt: disable-next-item
            isValid := and(
                    // Whether the returndata is the magic value `0x1626ba7e` (left-aligned).
                    eq(mload(d), f),
                    // Whether the staticcall does not revert.
                    // This must be placed at the end of the `and` clause,
                    // as the arguments are evaluated from right to left.
                    staticcall(
                        gas(), // Remaining gas.
                        signer, // The `signer` address.
                        m, // Offset of calldata in memory.
                        add(signature.length, 0x64), // Length of calldata in memory.
                        d, // Offset of returndata.
                        0x20 // Length of returndata to write.
                    )
                )
            break
        }
    }
}
