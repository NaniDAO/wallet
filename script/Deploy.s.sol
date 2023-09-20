// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import {Script} from "@forge/Script.sol";
import {Wallet} from "src/Wallet.sol";

contract Deploy is Script {
    function run() public payable returns (Wallet w) {
        vm.startBroadcast();
        w = new Wallet(address(0));
        vm.stopBroadcast();
    }
}
