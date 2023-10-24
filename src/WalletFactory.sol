// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import {Wallet} from './Wallet.sol';

contract WalletFactory {
    function deploy(address owner, bytes32 salt) public payable returns (Wallet) {
        return new Wallet{value: msg.value, salt: salt}(owner);
    }
}
