// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

interface IERC6551 {
    function ownerOf(uint256) external view returns (address);
}

contract Wallet {
    event Executed(address indexed to, uint256 val, bytes data);
    event ValidatorUpdated(address indexed validator);

    error InvalidSignature();
    error Unauthorized();

    enum Op {
        call,
        delegatecall,
        create
    }

    address public validator;
    IERC6551 public immutable token;
    uint256 public immutable tokenId;
    bytes32 immutable domainSeparator = keccak256(
        abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("Wallet")),
            keccak256("1"),
            block.chainid,
            address(this)
        )
    );

    // Constructor...
    constructor(IERC6551 _token, uint256 _tokenId, address _validator) payable {
        token = _token;
        tokenId = _tokenId;
        if (_validator != address(0)) {
            validator = _validator;
        }
    }

    // Execute Op...
    function execute(address to, uint256 val, bytes calldata data, Op op) public payable {
        if (msg.sender != token.ownerOf(tokenId)) if (msg.sender != entryPoint) revert Unauthorized();
        _execute(to, val, data, op);
    }

    function execute(address to, uint256 val, bytes calldata data, Op op, bytes calldata sig) public payable {
        bytes32 hash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                keccak256(
                    abi.encode(
                        keccak256("Execute(address to,uint256 val,bytes data,uint8 op)"), to, val, keccak256(data), op
                    )
                )
            )
        );

        if (!isValidSignatureNowCalldata(token.ownerOf(tokenId), hash, sig)) revert InvalidSignature();

        _execute(to, val, data, op);
    }

    function _execute(address to, uint256 val, bytes memory data, Op op) internal {
        emit Executed(to, val, data);
        if (op == Op.call) {
            assembly {
                let success := call(gas(), to, val, add(data, 0x20), mload(data), gas(), 0x00)
                returndatacopy(0x00, 0x00, returndatasize())
                if iszero(success) { revert(0x00, returndatasize()) }
                return(0x00, returndatasize())
            }
        } else if (op == Op.delegatecall) {
            assembly {
                let success := delegatecall(gas(), to, add(data, 0x20), mload(data), gas(), 0x00)
                returndatacopy(0x00, 0x00, returndatasize())
                if iszero(success) { revert(0x00, returndatasize()) }
                return(0x00, returndatasize())
            }
        } else {
            assembly {
                let created := create(val, add(data, 0x20), mload(data))
                if iszero(created) { revert(0x00, 0x00) }
                mstore(0x00, created)
                return(0x00, 0x20)
            }
        }
    }

    // Receivers...
    receive() external payable {}

    function onERC721Received(address, address, uint256, bytes calldata) public payable returns (bytes4) {
        return this.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) public payable returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        public
        payable
        returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }

    // eip-165...
    function supportsInterface(bytes4 interfaceId) public pure returns (bool) {
        return interfaceId == this.supportsInterface.selector || interfaceId == this.onERC721Received.selector
            || interfaceId == this.onERC1155Received.selector || interfaceId == this.onERC1155BatchReceived.selector;
    }

    // eip-1271...
    function isValidSignature(bytes32 hash, bytes calldata sig) public view returns (bytes4) {
        if (isValidSignatureNowCalldata(token.ownerOf(tokenId), hash, sig)) return 0x1626ba7e;
        else return 0xffffffff;
    }

    // eip-4337...
    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        public
        payable
        returns (uint256 validationData)
    {
        if (msg.sender != entryPoint) revert Unauthorized();

        assembly ("memory-safe") {
            mstore(0x20, userOpHash) // Store into scratch space for keccak256.
            mstore(0x00, "\x00\x00\x00\x00\x19Ethereum Signed Message:\n32") // 28 bytes.
            userOpHash := keccak256(0x04, 0x3c) // `32 * 2 - (32 - 28) = 60 = 0x3c`.
        }

        validator == address(0)
            ? validationData = isValidSignatureNowCalldata(token.ownerOf(tokenId), userOpHash, userOp.signature) ? 0 : 1
            : validationData = Wallet(payable(validator)).validateUserOp(userOp, userOpHash, missingAccountFunds);

        if (missingAccountFunds != 0) {
            assembly {
                pop(call(gas(), caller(), missingAccountFunds, 0x00, 0x00, 0x00, 0x00))
            }
        }
    }

    // eip-5267...
    function eip712Domain()
        public
        view
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        )
    {
        fields = hex"0f"; // `0b01111`.
        (name, version) = ("Wallet", "1");
        chainId = block.chainid;
        verifyingContract = address(this);
        salt = salt; // `bytes32(0)`.
        extensions = extensions; // `new uint256[](0)`.
    }

    // Validator Setting...
    function updateValidator(address _validator) public payable {
        if (msg.sender != token.ownerOf(tokenId)) if (msg.sender != entryPoint) revert Unauthorized();
        validator = _validator;
        emit ValidatorUpdated(_validator);
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
