// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

contract SigHelper {
    enum Op {
        call,
        delegatecall,
        create
    }

    function buildDomainSeparator(address wallet) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("Wallet")),
                keccak256("1"),
                block.chainid,
                wallet
            )
        );
    }

    function buildEIP712Hash(address wallet, address to, uint256 val, bytes memory data, Op op)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                buildDomainSeparator(wallet),
                keccak256(
                    abi.encode(
                        keccak256("Execute(address to,uint256 val,bytes data,uint8 op)"), to, val, keccak256(data), op
                    )
                )
            )
        );
    }
}
