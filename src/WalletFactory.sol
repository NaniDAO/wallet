// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import {Wallet} from "./Wallet.sol";

contract WalletFactory {
    event Deploy(Wallet indexed wallet, address owner, address validator);

    function deploy(address owner, address entryPoint) public payable returns (Wallet wallet) {
        emit Deploy(
            wallet =
                new Wallet{value: msg.value, salt: keccak256(abi.encodePacked(owner, entryPoint))}(owner, entryPoint),
            owner,
            entryPoint
        );
    }

    function determine(address owner, address entryPoint) public view returns (address wallet, bool deployed) {
        wallet = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff),
                            address(this),
                            keccak256(abi.encodePacked(owner, entryPoint)),
                            keccak256(abi.encodePacked(type(Wallet).creationCode, abi.encode(owner, entryPoint)))
                        )
                    )
                )
            )
        );
        assembly {
            deployed := extcodesize(wallet)
        }
    }
}
