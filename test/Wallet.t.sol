// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import "@forge/Test.sol";

import "../src/Wallet.sol";
import "../src/WalletFactory.sol";

import "@forge/Test.sol";

import {MockERC721} from "@solady/test/utils/mocks/MockERC721.sol";
import {MockERC1155} from "@solady/test/utils/mocks/MockERC1155.sol";

contract WalletTest is Test {
    event Execute(address indexed to, uint256 val, bytes data);

    address alice;
    uint256 aliceKey;

    address bob;
    uint256 bobKey;

    address constant entryPoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    Wallet w;
    MockERC721 erc721;
    MockERC1155 erc1155;

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function setUp() public payable {
        (alice, aliceKey) = makeAddrAndKey("alice");
        (bob, bobKey) = makeAddrAndKey("bob");

        WalletFactory f = new WalletFactory();
        w = f.deploy(alice);

        payable(address(w)).transfer(100 ether);

        erc721 = new MockERC721();
        erc1155 = new MockERC1155();
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testInitialOwner() public payable {
        assertEq(w.owner(), alice);
    }

    function testInitialBalance() public payable {
        assertEq(address(w).balance, 100 ether);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testExecuteCall() public payable {
        vm.prank(entryPoint);
        w.execute(bob, 0, abi.encodeWithSignature("foo()"), false);
    }

    function testExecuteDelegatecall() public payable {
        vm.prank(entryPoint);
        w.execute(bob, 0, abi.encodeWithSignature("foo()"), true);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testExecuteETHTransfer() public payable {
        vm.prank(entryPoint);
        w.execute(bob, 1 ether, "", false);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testFailNonOwnerExecute() public payable {
        vm.prank(bob);
        w.execute(bob, 1 ether, "", false);
    }

    function testIsValidSignature() public payable {
        bytes32 hash = keccak256(bytes("FOO"));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, hash);
        bytes memory sig = abi.encodePacked(r, s, v);

        bytes4 selector = w.isValidSignature(hash, sig);

        assert(selector == 0x1626ba7e);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testOnERC721Received() public payable {
        erc721.mint(alice, 1);
        vm.prank(alice);
        erc721.safeTransferFrom(alice, address(w), 1);
    }

    function testOnERC1155Received() public payable {
        erc1155.mint(alice, 1, 1, "");
        vm.prank(alice);
        erc1155.safeTransferFrom(alice, address(w), 1, 1, "");
    }

    function testOnERC1155BatchReceived() public payable {
        erc1155.mint(alice, 1, 1, "");
        vm.prank(alice);
        uint256[] memory ids = new uint256[](1);
        ids[0] = 1;
        uint256[] memory amts = new uint256[](1);
        amts[0] = 1;
        erc1155.safeBatchTransferFrom(alice, address(w), ids, amts, "");
    }
}

contract Dummy {}
