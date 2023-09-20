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
    constructor(address _owner) payable {
        owner = _owner;
    }

    // Execute Op...
    function execute(address to, uint256 val, bytes calldata data, Op op) public payable {
        if (msg.sender != owner) if (msg.sender != entryPoint) revert Unauthorized();

        bytes memory dataMem = data; // Copy `data` from calldata.

        emit Execute(to, val, data);

        assembly ("memory-safe") {
            // `Op.call`.
            if eq(op, 0) {
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
        if (msg.sender != entryPoint) revert Unauthorized();

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

import "./Meta.sol";
