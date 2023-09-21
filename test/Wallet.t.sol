// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import "../src/Wallet.sol";
import "@forge/Test.sol";

contract WalletTest is Test {
    event Execute(address indexed to, uint256 val, bytes data);
    event UpdateValidator(address indexed validator);

    address alice;
    uint256 aliceKey;

    address bob;
    uint256 bobKey;

    address immutable validator = makeAddr("validator");

    Wallet w;

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function setUp() public payable {
        (alice, aliceKey) = makeAddrAndKey("alice");
        (bob, bobKey) = makeAddrAndKey("bob");

        w = new Wallet(alice);
        payable(address(w)).transfer(100 ether);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testDeploy() public payable {
        new Wallet(alice);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testInitialOwner() public {
        assertEq(w.owner(), alice);
    }

    function testInitialBalance() public {
        assertEq(address(w).balance, 100 ether);
    }

    function testOnERC721Received() public {
        assert(w.onERC721Received(address(0), address(0), 0, "") == 0x150b7a02);
    }

    function testSupportsInterface() public {
        assertTrue(w.supportsInterface(0x01ffc9a7));
        assertTrue(w.supportsInterface(0x150b7a02));
        assertTrue(w.supportsInterface(0x4e2312e0));
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testExecuteCall() public payable {
        vm.prank(entryPoint);
        w.execute(bob, 0, abi.encodeWithSignature("foo()"), Wallet.Op.call);
    }

    function testExecuteCallEvent() public payable {
        vm.prank(entryPoint);
        vm.expectEmit(true, true, true, false);
        emit Execute(bob, 0, abi.encodeWithSignature("foo()"));
        w.execute(bob, 0, abi.encodeWithSignature("foo()"), Wallet.Op.call);
    }

    function testExecuteDelegatecall() public payable {
        vm.prank(entryPoint);
        w.execute(bob, 0, abi.encodeWithSignature("foo()"), Wallet.Op.delegatecall);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testExecuteETHTransfer() public payable {
        vm.prank(entryPoint);
        w.execute(bob, 1 ether, "", Wallet.Op.call);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testFailNonOwnerExecute() public {
        vm.prank(bob);
        w.execute(bob, 1 ether, "", Wallet.Op.call);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    /*function testExecuteCallEvent() public payable {
        vm.prank(alice);
        vm.expectEmit(true, true, true, false);
        emit Execute(bob, 0, abi.encodeWithSignature("foo()"));
        w.execute(bob, 0, abi.encodeWithSignature("foo()"), Wallet.Op.call);
    }*/
}

contract Dummy {}
