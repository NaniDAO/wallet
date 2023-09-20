// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import "./Wallet.sol";
import "../lib/solady/src/tokens/ERC721.sol";

contract WalletFactory {
    event Deployed(Wallet w, IERC6551 token, uint256 tokenId, address validator);

    function deploy(IERC6551 token, uint256 tokenId, address validator) public payable returns (Wallet w) {
        w = new Wallet{value: msg.value, salt: keccak256(abi.encodePacked(token, tokenId))}(token, tokenId, validator);
        emit Deployed(w, token, tokenId, validator);
    }

    function determine(IERC6551 token, uint256 tokenId, address validator) public view returns (address w, bool deployed) {
        w = address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), keccak256(abi.encodePacked(token, tokenId, validator)))))));
        assembly {
            deployed := extcodesize(w)
        }
    }
}
