// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import {Wallet} from "./Wallet.sol";

contract WalletFactory {
    event Deploy(Wallet indexed wallet);

    function deploy(address owner) public payable returns (Wallet wallet) {
        emit Deploy(wallet = new Wallet{value: msg.value, salt: bytes32(abi.encodePacked(owner))}(owner));
    }
}
