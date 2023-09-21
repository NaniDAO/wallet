// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import "./Meta.sol";

contract Wallet {
    enum Op {
        call,
        delegatecall
    }

    address public immutable owner;

    // Constructor...
    constructor(address _owner) payable {
        owner = _owner;
    }

    // Execute Op...
    function execute(address to, uint256 val, bytes calldata data, Op op) public payable {
        assembly {
            if iszero(eq(caller(), entryPoint)) { revert(0, 0) }
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
        validationData = isValidSignatureNowCalldata(owner, userOpHash, userOp.signature) ? 0 : 1;

        if (missingAccountFunds != 0) {
            assembly ("memory-safe") {
                pop(call(gas(), caller(), missingAccountFunds, 0x00, 0x00, 0x00, 0x00))
            }
        }
    }
}
