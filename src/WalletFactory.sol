// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import {Wallet} from "./Wallet.sol";

contract WalletFactory {
    // todo: assembly log event
    // use assembly create2
    event Deploy(Wallet indexed wallet);

    function deploy(bytes32 owner) public payable returns (Wallet wallet) {
        emit Deploy(wallet = new Wallet{value: msg.value, salt: owner}(owner));
    }
}
