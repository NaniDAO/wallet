// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import "../src/Wallet.sol";
import "@forge/Test.sol";

contract ECDSA {
    function getDomainSeparator(address wallet) internal view returns (bytes32 domainSeparator) {
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

    function toEthSignedMessageHash(bytes32 messageHash) internal pure returns (bytes32 digest) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, "\x19Ethereum Signed Message:\n32") // 32 is the bytes-length of messageHash
            mstore(0x1c, messageHash) // 0x1c (28) is the length of the prefix
            digest := keccak256(0x00, 0x3c) // 0x3c is the length of the prefix (0x1c) + messageHash (0x20)
        }
    }

    function to712Hash(address wallet, address to, uint256 val, bytes memory data, Wallet.Op op)
        public
        view
        returns (bytes32 digest)
    {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                getDomainSeparator(wallet),
                keccak256(
                    abi.encode(
                        keccak256("Execute(address to,uint256 val,bytes data,uint8 op)"), to, val, keccak256(data), op
                    )
                )
            )
        );
    }
}

contract WalletTest is Test, ECDSA {
    Wallet w;

    address alice;
    uint256 aliceKey;

    address bob;
    uint256 bobKey;

    function setUp() public payable {
        (alice, aliceKey) = makeAddrAndKey("alice");
        (bob, bobKey) = makeAddrAndKey("bob");

        w = new Wallet(alice, address(0));
        payable(address(w)).transfer(100 ether);
    }

    function testDeploy() public payable {
        new Wallet(alice, address(0));
    }

    function testExecute() public payable {
        vm.prank(alice);
        w.execute(bob, 0, abi.encodeWithSignature("foo()"), Wallet.Op.call);
    }

    function testExecuteWithSig() public payable {
        vm.startPrank(alice);

        bytes memory data = abi.encodeWithSignature("foo()");
        bytes32 digest = to712Hash(address(w), bob, uint256(0), data, Wallet.Op.call);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        w.execute(bob, 0, data, Wallet.Op.call, sig);

        vm.stopPrank();
    }
}
