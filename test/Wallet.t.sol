// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import '@forge/Test.sol';

import '../src/Wallet.sol';
import '../src/WalletFactory.sol';

import '@forge/Test.sol';

import {MockERC20} from '@solady/test/utils/mocks/MockERC20.sol';
import {MockERC721} from '@solady/test/utils/mocks/MockERC721.sol';
import {MockERC1155} from '@solady/test/utils/mocks/MockERC1155.sol';
import {MockERC1271Wallet} from '@solady/test/utils/mocks/MockERC1271Wallet.sol';

interface IEntryPoint {
    function getUserOpHash(Wallet.UserOperation calldata userOp) external view returns (bytes32);
    function handleOps(Wallet.UserOperation[] calldata ops, address payable beneficiary) external;
    function getNonce(address sender, uint192 key) external view returns (uint nonce);
}

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

    address erc20;
    bytes32 erc20Hash;

    MockERC721 erc721;
    MockERC1155 erc1155;
    MockERC1271Wallet contractWallet;

    EthFwd ethFwd;

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function setUp() public payable {
        // Create Ethereum fork.
        vm.createSelectFork(vm.rpcUrl('main'));

        (aliceAddr, aliceKey) = makeAddrAndKey('alice');
        (bobAddr, bobKey) = makeAddrAndKey('bob');

        WalletFactory f = new WalletFactory();
        w = f.deploy(alice = bytes32(uint(uint160(aliceAddr))));

        bob = bytes32(uint(uint160(bobAddr)));

        payable(address(w)).transfer(100 ether);

        erc20 = address(new MockERC20("TEST", "TEST", 18));
        erc20Hash = bytes32(uint(uint160(erc20)));
        erc721 = new MockERC721();
        erc1155 = new MockERC1155();

        MockERC20(erc20).mint(bobAddr, 1000 ether);
        MockERC20(erc20).mint(address(w), 10000 ether);

        contractWallet = new MockERC1271Wallet(address(aliceAddr));
        contractOwnedW = f.deploy(bytes32(uint(uint160(address(contractWallet)))));
        ethFwd = new EthFwd();
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

    function testFailExecuteCallNotEntrypoint() public payable {
        w.execute(bob, abi.encodeWithSignature('foo()'));
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testExecuteDelegatecall() public payable {
        vm.prank(entryPoint);
        w.execute(bob, abi.encodeWithSignature('foo()'));
    }

    function testExecuteETHTransfer() public payable {
        vm.prank(entryPoint);
        // Execute the delegatecall to the forwarder
        w.execute(
            bytes32(uint(uint160(address(ethFwd)))),
            abi.encodeWithSelector(ethFwd.fwdETH.selector, bobAddr, 1 ether)
        );
    }

    function testExecuteETHTransferResult() public payable {
        assertEq(bobAddr.balance, 0 ether);
        vm.prank(entryPoint);

        // Prepare the call data for the forwarder
        bytes memory data = abi.encodeWithSelector(ethFwd.fwdETH.selector, bobAddr, 1 ether);

        // Execute the delegatecall to the forwarder
        w.execute(bytes32(uint(uint160(address(ethFwd)))), data);

        // Verify that the Ether got transferred
        assertEq(bobAddr.balance, 1 ether);
    }

    function testExecuteERC20Transfer() public payable {
        vm.prank(entryPoint);
        // Execute the delegatecall to the ERC20
        w.execute(
            erc20Hash,
            abi.encodeWithSelector(MockERC20.transfer.selector, bobAddr, 0) // of tokens.
        );
    }

    /*function testExecuteERC721Transfer() public payable {
        erc721.mint(address(w), 1);
        bytes memory data =
            abi.encodeWithSelector(MockERC721.transferFrom.selector, address(w), bobAddr, 1);
        vm.prank(entryPoint);
        w.execute(bytes32(uint(uint160(address(erc721)))), data);
    }*/

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testFailNonOwnerExecute() public payable {
        vm.prank(bobAddr);
        w.execute(bob, '');
    }

    function testIsValidSignature() public payable {
        bytes32 hash = keccak256(abi.encodePacked('FOO'));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, hash);
        bytes memory sig = abi.encodePacked(r, s, v);
        // ABI encode hash and sig as expected by isValidSignature.
        bytes memory data = abi.encodeWithSelector(0x1626ba7e, hash, sig);
        (, bytes memory ret) = address(w).staticcall(data);

        bytes4 selector;
        assembly {
            selector := mload(add(ret, 0x20))
        }

        assert(selector == 0x1626ba7e);
    }

    // function testIsValidSignatureFromContract() public payable {
    //     bytes32 hash = keccak256(bytes('FOO'));

    //     (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, hash);
    //     bytes memory sig = abi.encodePacked(r, s, v);

    //     bytes4 selector = contractWallet.isValidSignature(hash, sig);

    //     assert(selector == 0x1626ba7e);
    // }

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

    function createUserOp(uint pK, uint192 key)
        internal
        view
        returns (Wallet.UserOperation memory userOp)
    {
        userOp.sender = address(w);
        userOp.nonce = IEntryPoint(entryPoint).getNonce(userOp.sender, key);
        userOp.initCode = bytes('');
        userOp.callData = bytes('');
        userOp.callGasLimit = 0;
        userOp.verificationGasLimit = 0;
        userOp.preVerificationGas = 0;
        userOp.maxFeePerGas = 0;
        userOp.maxPriorityFeePerGas = 0;
        userOp.paymasterAndData = bytes('');
        userOp.signature = sign(pK, IEntryPoint(entryPoint).getUserOpHash(userOp));
    }

    function testValidateUserOp() public payable {
        Wallet.UserOperation memory userOp = createUserOp(aliceKey, 0);
        bytes32 userOpHash = IEntryPoint(entryPoint).getUserOpHash(userOp);
        vm.prank(entryPoint);

        uint validationData = w.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0);
    }

    /*function testBadValidateUserOp() public payable {
        Wallet.UserOperation memory userOp = createUserOp(bobKey, 0);
        bytes32 userOpHash = IEntryPoint(entryPoint).getUserOpHash(userOp);
        vm.prank(entryPoint);
        uint validationData = w.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 1);
    }*/

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function sign(uint pK, bytes32 hash) internal pure returns (bytes memory sig) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pK, hash);
        sig = abi.encodePacked(r, s, v);
    }
}

contract EthFwd {
    function fwdETH(address to, uint amount) public payable {
        /// @solidity memory-safe-assembly
        assembly {
            if iszero(call(gas(), to, amount, gas(), 0x00, gas(), 0x00)) {
                mstore(0x00, 0xb12d13eb) // `ETHTransferFailed()`.
                revert(0x1c, 0x04)
            }
        }
    }
}
