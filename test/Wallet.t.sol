// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import '@forge/Test.sol';

import '../src/Wallet.sol';
import '../src/WalletFactory.sol';

import '@forge/Test.sol';

import {MockERC721} from '@solady/test/utils/mocks/MockERC721.sol';
import {MockERC1155} from '@solady/test/utils/mocks/MockERC1155.sol';
import {MockERC1271Wallet} from "@solady/test/utils/mocks/MockERC1271Wallet.sol";

contract WalletTest is Test {
    address aliceAddr;
    bytes32 alice;
    uint aliceKey;

    address bobAddr;
    bytes32 bob;
    uint bobKey;

    address constant entryPoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    Wallet w;
    Wallet contractOwnedW;
    MockERC721 erc721;
    MockERC1155 erc1155;
    MockERC1271Wallet contractWallet;

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function setUp() public payable {
        // Create Ethereum fork.
        vm.createSelectFork(vm.rpcUrl("main"));

        (aliceAddr, aliceKey) = makeAddrAndKey('alice');
        (bobAddr, bobKey) = makeAddrAndKey('bob');

        WalletFactory f = new WalletFactory();
        w = f.deploy(alice = bytes32(uint(uint160(aliceAddr))));

        bob = bytes32(uint(uint160(bobAddr)));

        payable(address(w)).transfer(100 ether);

        erc721 = new MockERC721();
        erc1155 = new MockERC1155();

        contractWallet = new MockERC1271Wallet(address(aliceAddr));
        contractOwnedW = f.deploy(bytes32(uint(uint160(address(contractWallet)))));
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testInitialBalance() public payable {
        assertEq(address(w).balance, 100 ether);
    }

    function testReceiveETH() public payable {
        payable(address(w)).transfer(100 ether);
        assertEq(address(w).balance, 200 ether);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testExecuteCall() public payable {
        vm.prank(entryPoint);
        w.execute(bob, 0, abi.encodeWithSignature('foo()'), 0);
    }

    function testExecuteDelegatecall() public payable {
        vm.prank(entryPoint);
        w.execute(bob, 0, abi.encodeWithSignature('foo()'), 1);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testExecuteETHTransfer() public payable {
        vm.prank(entryPoint);
        w.execute(bob, 1 ether, '', 0);
    }

    function testExecuteETHTransferResult() public payable {
        assertEq(bobAddr.balance, 0 ether);
        vm.prank(entryPoint);
        w.execute(bob, 1 ether, '', 0);
        assertEq(bobAddr.balance, 1 ether);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testFailNonOwnerExecute() public payable {
        vm.prank(bobAddr);
        w.execute(bob, 1 ether, '', 0);
    }

    function testIsValidSignature() public payable {
        bytes32 hash = keccak256(bytes('FOO'));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, hash);
        bytes memory sig = abi.encodePacked(r, s, v);

        bytes4 selector = w.isValidSignature(hash, sig);

        assert(selector == 0x1626ba7e);
    }

    function testIsValidSignatureFromContract() public payable {
        bytes32 hash = keccak256(bytes('FOO'));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, hash);
        bytes memory sig = abi.encodePacked(r, s, v);

        bytes4 selector = contractWallet.isValidSignature(hash, sig);

        assert(selector == 0x1626ba7e);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testOnERC721Received() public payable {
        erc721.mint(aliceAddr, 1);
        vm.prank(aliceAddr);
        erc721.safeTransferFrom(aliceAddr, address(w), 1);
    }

    function testOnERC1155Received() public payable {
        erc1155.mint(aliceAddr, 1, 1, '');
        vm.prank(aliceAddr);
        erc1155.safeTransferFrom(aliceAddr, address(w), 1, 1, '');
    }

    function testOnERC1155BatchReceived() public payable {
        erc1155.mint(aliceAddr, 1, 1, '');
        vm.prank(aliceAddr);
        uint[] memory ids = new uint256[](1);
        ids[0] = 1;
        uint[] memory amts = new uint256[](1);
        amts[0] = 1;
        erc1155.safeBatchTransferFrom(aliceAddr, address(w), ids, amts, '');
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////
    
    function testValidateUserOp() public payable {
        vm.prank(entryPoint);

        wallet.validateUserOp(userOp)
    }
}
