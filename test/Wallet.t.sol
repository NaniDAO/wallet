// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import "./utils/SigHelper.sol";
import "../src/Wallet.sol";
import "@forge/Test.sol";

contract WalletTest is Test, SigHelper {
    Wallet w;

    address alice;
    uint256 aliceKey;

    address bob;
    uint256 bobKey;

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function setUp() public payable {
        (alice, aliceKey) = makeAddrAndKey("alice");
        (bob, bobKey) = makeAddrAndKey("bob");

        w = new Wallet(alice, address(0));
        payable(address(w)).transfer(100 ether);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testDeploy() public payable {
        new Wallet(alice, address(0));
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
        w.execute(address(0), 0, type(SigHelper).creationCode, Wallet.Op.create);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testExecuteETHTransfer() public payable {
        vm.prank(alice);
        w.execute(bob, 1 ether, "", Wallet.Op.call);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testExecuteWithSig() public payable {
        vm.startPrank(alice);

        bytes memory data = abi.encodeWithSignature("foo()");
        bytes32 digest = buildEIP712Hash(address(w), bob, uint256(0), data, SigHelper.Op.call);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        w.execute(bob, 0, data, Wallet.Op.call, sig);

        vm.stopPrank();
    }
}
