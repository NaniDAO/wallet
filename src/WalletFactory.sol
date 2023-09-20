// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import {Wallet} from "./Wallet.sol";

contract WalletFactory {
    event Deployed(Wallet w, address owner, address validator);

    function deploy(address owner, address validator) public payable returns (Wallet w) {
        w = new Wallet{value: msg.value, salt: keccak256(abi.encodePacked(owner))}(owner, validator);
        emit Deployed(w, owner, validator);
    }

    function determine(address owner, address validator) public view returns (address w, bool deployed) {
        w = address(
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
            deployed := extcodesize(w)
        }
    }
}
