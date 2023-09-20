// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

contract Wallet {
    event Execute(address indexed to, uint256 val, bytes data);
    event UpdateValidator(address indexed validator);

    error InvalidSignature();
    error Unauthorized();

    enum Op {
        call,
        delegatecall,
        create
    }

    address public validator;
    address public immutable owner;

    // Constructor...
    constructor(address _owner, address _validator) payable {
        owner = _owner;
        assembly ("memory-safe") {
            // Store if non-zero `_validator`.
            if _validator { sstore(0, _validator) }
        }
    }

    // Execute Op...
    function execute(address to, uint256 val, bytes calldata data, Op op) public payable {
        if (msg.sender != owner) if (msg.sender != entryPoint) revert Unauthorized();
        _execute(to, val, data, op);
    }

    function _execute(address to, uint256 val, bytes memory data, Op op) internal {
        emit Execute(to, val, data);

        assembly ("memory-safe") {
            // if (op == Op.call)...
            if eq(op, 0) {
                // Perform a `call()` with the given parameters.
                let success := call(gas(), to, val, add(data, 0x20), mload(data), gas(), 0x00)
                // Copy the returned data to memory.
                returndatacopy(0x00, 0x00, returndatasize())
                // Revert if the `call()` was unsuccessful.
                if iszero(success) { revert(0x00, returndatasize()) }
                // Otherwise, return the data.
                return(0x00, returndatasize())
            }
            // if (op == Op.delegatecall)...
            if eq(op, 1) {
                // Perform a `delegatecall()` with the given parameters.
                let success := delegatecall(gas(), to, add(data, 0x20), mload(data), gas(), 0x00)
                // Copy the returned data to memory.
                returndatacopy(0x00, 0x00, returndatasize())
                // Revert if the `delegatecall()` was unsuccessful.
                if iszero(success) { revert(0x00, returndatasize()) }
                // Otherwise, return the data.
                return(0x00, returndatasize())
            }
            // else, Op.create...
            let created := create(val, add(data, 0x20), mload(data))
            // Revert if contract creation was unsuccessful.
            if iszero(created) { revert(0x00, 0x00) }
            // Otherwise, copy the address to memory.
            mstore(0x00, created)
            // Return the address.
            return(0x00, 0x20)
        }
    }

    // Receivers...
    receive() external payable {}

    function onERC721Received(address, address, uint256, bytes calldata) public payable returns (bytes4) {
        assembly ("memory-safe") {
            mstore(0x00, 0x150b7a02) // `ERC721Received`.
            return(0x00, 0x04) // Return 4 bytes.
        }
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) public payable returns (bytes4) {
        assembly ("memory-safe") {
            mstore(0x00, 0x4e2312e0) // `ERC1155Received`.
            return(0x00, 0x04) // Return 4 bytes.
        }
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        public
        payable
        returns (bytes4)
    {
        assembly ("memory-safe") {
            mstore(0x00, 0xeb9a5567) // `ERC1155BatchReceived`.
            return(0x00, 0x04) // Return 4 bytes.
        }
    }

    // eip-165...
    function supportsInterface(bytes4 interfaceId) public pure returns (bool supported) {
        assembly ("memory-safe") {
            let s := shr(224, interfaceId) //...ERC721TokenReceiver/ERC1155TokenReceiver.
            supported := or(eq(s, 0x01ffc9a7), or(eq(s, 0x150b7a02), eq(s, 0x4e2312e0)))
        }
    }

    // eip-1271...
    function isValidSignature(bytes32 hash, bytes calldata sig) public view returns (bytes4) {
        if (isValidSignatureNowCalldata(owner, hash, sig)) return 0x1626ba7e;
        else return 0xffffffff;
    }

    // eip-4337...
    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        public
        payable
        returns (uint256 validationData)
    {
        if (msg.sender != entryPoint) revert Unauthorized();

        // (solady/blob/main/src/utils/ECDSA.sol)
        assembly ("memory-safe") {
            mstore(0x20, userOpHash) // Store into scratch space for keccak256.
            mstore(0x00, "\x00\x00\x00\x00\x19Ethereum Signed Message:\n32") // 28 bytes.
            userOpHash := keccak256(0x04, 0x3c) // `32 * 2 - (32 - 28) = 60 = 0x3c`.
        }

        validator == address(0)
            ? validationData = isValidSignatureNowCalldata(owner, userOpHash, userOp.signature) ? 0 : 1
            : validationData = Wallet(payable(validator)).validateUserOp(userOp, userOpHash, missingAccountFunds);

        if (missingAccountFunds != 0) {
            assembly {
                pop(call(gas(), caller(), missingAccountFunds, 0x00, 0x00, 0x00, 0x00))
            }
        }
    }

    // Validator Setting...
    function updateValidator(address _validator) public payable {
        if (msg.sender != owner) if (msg.sender != entryPoint) revert Unauthorized();
        assembly ("memory-safe") {
            sstore(0, _validator)
        }
        emit UpdateValidator(_validator);
    }
}

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
