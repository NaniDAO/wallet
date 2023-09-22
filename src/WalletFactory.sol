// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import {Wallet} from "./Wallet.sol";

contract WalletFactory {
    function deploy(bytes32 ownerAndSalt) public payable returns (Wallet wallet) {
        // Prepare just the contract creation code outside of assembly
        bytes memory code = type(Wallet).creationCode;
        // Perform the append and create2 operation within assembly
        assembly {
            let codeSize := mload(code) // Get the size of the creation code
            let codeData := add(code, 0x20) // Skip the length field to get to the data part

            // Append ownerAndSalt to the end and calculate full code size
            mstore(add(codeData, codeSize), ownerAndSalt)
            let fullCodeSize := add(codeSize, 0x20) // Increase size by 32 bytes (size of bytes32)

            // Perform create2 with call value, pointing to the start of the code, its size, and the salt
            wallet := create2(callvalue(), codeData, fullCodeSize, ownerAndSalt)
            if iszero(wallet) { revert(0, 0) } // Revert if create2 fails
        }
    }
}
