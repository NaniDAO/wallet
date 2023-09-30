// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import '@forge/Test.sol';

import '../src/Wallet.sol';
import '../src/WalletFactory.sol';

import {MockERC20} from '@solady/test/utils/mocks/MockERC20.sol';
import {MockERC721} from '@solady/test/utils/mocks/MockERC721.sol';
import {MockERC1155} from '@solady/test/utils/mocks/MockERC1155.sol';
import {MockERC1271Wallet} from '@solady/test/utils/mocks/MockERC1271Wallet.sol';

contract WalletTest is Test {
    address constant entryPoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    address alice;
    bytes32 aliceHash;
    uint aliceKey;

    address bob;
    bytes32 bobHash;
    uint bobKey;

    MockERC20 erc20;
    bytes32 erc20Hash;
    MockERC721 erc721;
    bytes32 erc721Hash;
    MockERC1155 erc1155;
    bytes32 erc1155Hash;

    Wallet w;
    Wallet contractOwnedW;
    MockERC1271Wallet contractWallet;

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function setUp() public payable {
        vm.createSelectFork(vm.rpcUrl('main')); // Eth fork.

        (alice, aliceKey) = makeAddrAndKey('alice');
        (bob, bobKey) = makeAddrAndKey('bob');

        aliceHash = bytes32(uint(uint160(alice)));
        bobHash = bytes32(uint(uint160(bob)));

        WalletFactory f = new WalletFactory();
        w = f.deploy(aliceHash);

        payable(address(w)).transfer(100 ether); // Send ETH.

        erc20 = new MockERC20("Test", "TEST", 18);
        erc20Hash = bytes32(uint(uint160(address(erc20))));
        erc721 = new MockERC721();
        erc721Hash = bytes32(uint(uint160(address(erc721))));
        erc1155 = new MockERC1155();
        erc1155Hash = bytes32(uint(uint160(address(erc1155))));

        MockERC20(erc20).mint(bob, 100 ether); // Mint usr tokens.
        MockERC20(erc20).mint(address(w), 1000 ether); // Mint wallet tokens.

        erc721.mint(address(w), 1); // Mint wallet NFT.
        erc721.mint(alice, 2); // Mint usr NFT.
        erc1155.mint(address(w), 1, 1, ''); // Mint wallet ERC1155.

        contractWallet = new MockERC1271Wallet(alice); // Placeholder contract w.
        contractOwnedW = f.deploy(bytes32(uint(uint160(address(contractWallet)))));
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testReceiveETH() public payable {
        payable(address(w)).transfer(100 ether);
        assertEq(address(w).balance, 200 ether);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testExecuteAsOwner() public payable {
        vm.prank(alice);
        w.execute(bobHash, 0, abi.encodeWithSignature('foo()'), 1); // `1` is call().
    }

    function testExecuteAsEntryPoint() public payable {
        vm.prank(entryPoint);
        w.execute(bobHash, 0, abi.encodeWithSignature('foo()'), 1);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testFailExecuteAsNotEntrypointOrOwner() public payable {
        w.execute(bobHash, 0, abi.encodeWithSignature('foo()'), 1);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testExecuteDelegatecall() public payable {
        vm.prank(entryPoint);
        w.execute(bobHash, 0, abi.encodeWithSignature('foo()'), 0); // `0` is delegatecall().
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testExecuteETHTransfer() public payable {
        vm.prank(entryPoint);
        w.execute(bobHash, 1 ether, '', 1);
    }

    function testExecuteETHTransferAndCheckResult() public payable {
        assertEq(bob.balance, 0 ether);
        vm.prank(entryPoint);
        w.execute(bobHash, 1 ether, '', 1);
        assertEq(bob.balance, 1 ether);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testExecuteERC20Transfer() public payable {
        vm.prank(entryPoint);
        w.execute(
            erc20Hash,
            0,
            abi.encodeWithSelector(MockERC20.transfer.selector, alice, 100 ether), // of tokens.
            1
        );
    }

    function testExecuteERC20TransferWarm() public payable {
        vm.prank(entryPoint);
        w.execute(
            erc20Hash,
            0,
            abi.encodeWithSelector(MockERC20.transfer.selector, bob, 100 ether), // of tokens.
            1
        );
    }

    function testExecuteERC20TransferAndCheckResult() public payable {
        assertEq(erc20.balanceOf(bob), 100 ether);
        vm.prank(entryPoint);
        w.execute(
            erc20Hash,
            0,
            abi.encodeWithSelector(MockERC20.transfer.selector, bob, 100 ether), // of tokens.
            1
        );
        assertEq(erc20.balanceOf(bob), 200 ether);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testExecuteERC721Transfer() public payable {
        vm.prank(entryPoint);
        w.execute(
            erc721Hash,
            0,
            abi.encodeWithSelector(MockERC721.transferFrom.selector, address(w), bob, 1), // id of token.
            1
        );
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testIsValidSignature() public payable {
        bytes32 hash = keccak256(abi.encodePacked('foo()'));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, hash);
        // ABI encode hash and sig as expected by isValidSignature() / eip-1271.
        bytes memory data = abi.encodeWithSelector(0x1626ba7e, hash, abi.encode(v, r, s));
        (, bytes memory ret) = address(w).staticcall(data);

        bytes4 selector; // Slice selector return.
        assembly {
            selector := mload(add(ret, 0x20))
        }

        assert(selector == 0x1626ba7e); // Check match.
    }

    // function testIsValidSignatureFromContract() public payable { // note: placeholder.
    //     bytes32 hash = keccak256(bytes('FOO'));

    //     (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, hash);
    //     bytes memory sig = abi.encodePacked(r, s, v);

    //     bytes4 selector = contractWallet.isValidSignature(hash, sig);

    //     assert(selector == 0x1626ba7e);
    // }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testOnERC721Received() public payable {
        vm.prank(alice);
        erc721.safeTransferFrom(alice, address(w), 2);
    }

    function testOnERC1155Received() public payable {
        erc1155.mint(alice, 1, 1, '');
        vm.prank(alice);
        erc1155.safeTransferFrom(alice, address(w), 1, 1, '');
    }

    function testOnERC1155BatchReceived() public payable {
        erc1155.mint(alice, 1, 1, '');
        vm.prank(alice);
        uint[] memory ids = new uint256[](1);
        ids[0] = 1;
        uint[] memory amts = new uint256[](1);
        amts[0] = 1;
        erc1155.safeBatchTransferFrom(alice, address(w), ids, amts, '');
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function createUserOp(uint pK, uint192 key)
        internal
        view
        returns (Wallet.UserOperation memory userOp)
    {
        userOp.sender = address(w);
        userOp.nonce = IEntryPoint(entryPoint).getNonce(userOp.sender, key);
        // Null most.
        userOp.initCode;
        userOp.callData;
        userOp.callGasLimit;
        userOp.verificationGasLimit;
        userOp.preVerificationGas;
        userOp.maxFeePerGas;
        userOp.maxPriorityFeePerGas;
        userOp.paymasterAndData;
        userOp.signature = sign(pK, IEntryPoint(entryPoint).getUserOpHash(userOp));
    }

    function testValidateUserOp() public payable {
        // Success case.
        Wallet.UserOperation memory userOp = createUserOp(aliceKey, 0);
        bytes32 userOpHash = IEntryPoint(entryPoint).getUserOpHash(userOp);

        vm.prank(entryPoint); // Call as EP and check valid.
        assertEq(w.validateUserOp(userOp, userOpHash, 0), 0); // Return `0` for valid.
    }

    function testBadValidateUserOp() public payable {
        // Fail case.
        Wallet.UserOperation memory userOp = createUserOp(bobKey, 0);
        bytes32 userOpHash = IEntryPoint(entryPoint).getUserOpHash(userOp);

        vm.prank(entryPoint); // Call as EP and check valid.
        assertEq(w.validateUserOp(userOp, userOpHash, 0), 1); // Return `1` for invalid.
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function sign(uint pK, bytes32 hash) internal pure returns (bytes memory) {
        // Helper.
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pK, hash);
        return abi.encodePacked(r, s, v);
    }
}

interface IEntryPoint {
    function getUserOpHash(Wallet.UserOperation calldata userOp) external view returns (bytes32);
    function handleOps(Wallet.UserOperation[] calldata ops, address payable beneficiary) external;
    function getNonce(address sender, uint192 key) external view returns (uint nonce);
}
