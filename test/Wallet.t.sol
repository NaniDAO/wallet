// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import "../src/Wallet.sol";
import "@forge/Test.sol";

contract WalletTest is Test {
    address alice;
    uint256 aliceKey;

    address bob;
    uint256 bobKey;

    address immutable validator = makeAddr("validator");

    address constant entryPoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    Wallet w;

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function setUp() public payable {
        (alice, aliceKey) = makeAddrAndKey("alice");
        (bob, bobKey) = makeAddrAndKey("bob");

        w = new Wallet(alice, entryPoint);
        payable(address(w)).transfer(100 ether);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testDeploy() public payable {
        new Wallet(alice, entryPoint);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testInitialOwner() public {
        assertEq(w.owner(), alice);
    }

    function testInitialBalance() public {
        assertEq(address(w).balance, 100 ether);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testExecuteCall() public payable {
        vm.prank(alice);
        w.execute(bob, 0, abi.encodeWithSignature("foo()"), Wallet.Op.call);
    }

    function testExecuteDelegatecall() public payable {
        vm.prank(alice);
        w.execute(bob, 0, abi.encodeWithSignature("foo()"), Wallet.Op.delegatecall);
    }

    function testExecuteCreate() public payable {
        vm.prank(alice);
        w.execute(address(0), 0, type(Dummy).creationCode, Wallet.Op.create);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testExecuteETHTransfer() public payable {
        vm.prank(alice);
        w.execute(bob, 1 ether, "", Wallet.Op.call);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testFailNonOwnerExecute() public {
        vm.prank(bob);
        w.execute(bob, 1 ether, "", Wallet.Op.call);
    }
}

contract Dummy {}
