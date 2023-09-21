// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import "@forge/Test.sol";

import "../src/Wallet.sol";
import "../src/WalletFactory.sol";

import "@forge/Test.sol";

import {MockERC721} from "@solady/test/utils/mocks/MockERC721.sol";

contract WalletTest is Test {
    event Execute(address indexed to, uint256 val, bytes data);

    address alice;
    uint256 aliceKey;

    address bob;
    uint256 bobKey;

    address constant entryPoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    Wallet w;
    MockERC721 erc721;

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function setUp() public payable {
        (alice, aliceKey) = makeAddrAndKey("alice");
        (bob, bobKey) = makeAddrAndKey("bob");

        WalletFactory f = new WalletFactory();
        w = f.deploy(alice);

        payable(address(w)).transfer(100 ether);

        erc721 = new MockERC721();
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

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testOnERC721Received() public payable {
        erc721.mint(alice, 1);
        vm.prank(alice);
        //erc721.safeTransferFrom(alice, 1, w);
    }
}

contract Dummy {}
