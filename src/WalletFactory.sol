// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import {Wallet} from "./Wallet.sol";

contract WalletFactory {
    event Deploy(Wallet indexed wallet, address owner, address validator);

    function deploy(address owner, address validator) public payable returns (Wallet wallet) {
        emit Deploy(
            wallet = new Wallet{value: msg.value, salt: keccak256(abi.encodePacked(owner))}(owner, validator),
            owner,
            validator
        );
    }

    function determine(address owner, address validator) public view returns (address wallet, bool deployed) {
        wallet = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff),
                            address(this),
                            keccak256(abi.encodePacked(owner)),
                            keccak256(abi.encodePacked(type(Wallet).creationCode, abi.encode(owner, validator)))
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
