// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import "./Meta.sol";

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

    address public immutable owner;
    Wallet public validator;

    // Constructor...
    constructor(address _owner) payable {
        owner = _owner;
    }

    // Execute Op...
    function execute(address to, uint256 val, bytes calldata data, Op op) public payable {
        if (msg.sender != owner) if (msg.sender != entryPoint) revert Unauthorized();

        assembly {
            let dataMem := mload(data.offset) // Load `data` from calldata.
            // Event:
            log2(
                add(dataMem, 0x20), // Empty data location.
                mload(dataMem), // Data size.
                0x4a0de09071d37e2800c1dcc9027a0030cd5202f3a5a766952307470adc640c57, // `keccak256(bytes("Execute(address,uint256,bytes)"))`.
                to // Indexed `to`.
            )
            // `Op.call`.
            if iszero(op) {
                // Perform a `call()` with the given parameters.
                let success := call(gas(), to, val, add(dataMem, 0x20), mload(dataMem), gas(), 0x00)
                // Copy the returned data to memory.
                returndatacopy(0x00, 0x00, returndatasize())
                // Revert if the `call()` was unsuccessful.
                if iszero(success) { revert(0x00, returndatasize()) }
                // Otherwise, return the data.
                return(0x00, returndatasize())
            }
            // `Op.delegatecall`.
            if eq(op, 1) {
                // Perform a `delegatecall()` with the given parameters.
                let success := delegatecall(gas(), to, add(dataMem, 0x20), mload(dataMem), gas(), 0x00)
                // Copy the returned data to memory.
                returndatacopy(0x00, 0x00, returndatasize())
                // Revert if the `delegatecall()` was unsuccessful.
                if iszero(success) { revert(0x00, returndatasize()) }
                // Otherwise, return the data.
                return(0x00, returndatasize())
            }
            // `Op.create`.
            let created := create(val, add(dataMem, 0x20), mload(dataMem))
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
        assembly ("memory-safe") {
            if iszero(eq(caller(), entryPoint)) {
                // Revert if `msg.sender` is not `entryPoint`.
                revert(0x00, 0x00)
            }
        }

        Wallet val = validator;
        validationData = address(val) == address(0)
            ? isValidSignatureNowCalldata(owner, userOpHash, userOp.signature) ? 0 : 1
            : val.validateUserOp(userOp, userOpHash, missingAccountFunds);

        if (missingAccountFunds != 0) {
            // Refund `msg.sender` `entryPoint`.
            assembly ("memory-safe") {
                pop(call(gas(), caller(), missingAccountFunds, 0x00, 0x00, 0x00, 0x00))
            }
        }
    }

    // Validator Setting...
    function updateValidator(address _validator) public payable {
        if (msg.sender != owner) if (msg.sender != entryPoint) revert Unauthorized();

        assembly ("memory-safe") {
            // Store `_validator` in first storage slot.
            sstore(0, _validator)
            // Event:
            log2(
                mload(0x40), // Empty data location.
                0x00, // Data size.
                0x1e1fec57c7820d1f8245ceb19d2d2fd5d03b4b7b165475077ea520162ce40743, // `keccak256(bytes("UpdateValidator(address)"))`.
                _validator // Indexed `_validator`.
            )
        }
    }
}
