// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

address constant entryPoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

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