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

        WalletFactory f = new WalletFactory();
        w = f.deploy(alice, bytes32(0));

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
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testReceiveETH() public payable {
        payable(address(w)).transfer(100 ether);
        assertEq(address(w).balance, 200 ether);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testExecuteAsOwner() public payable {
        vm.prank(alice);
        w.execute(bob, 0, abi.encodeWithSignature('foo()'));
    }

    function testExecuteAsEntryPoint() public payable {
        vm.prank(entryPoint);
        w.execute(bob, 0, abi.encodeWithSignature('foo()'));
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testFailExecuteAsNotEntrypointOrOwner() public payable {
        w.execute(bob, 0, abi.encodeWithSignature('foo()'));
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testExecuteDelegatecall() public payable {
        vm.prank(entryPoint);
        w.execute(bob, type(uint).max, abi.encodeWithSignature('foo()'));
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testExecuteETHTransfer() public payable {
        vm.prank(entryPoint);
        w.execute(bob, 1 ether, '');
    }

    function testExecuteETHTransferAndCheckResult() public payable {
        assertEq(bob.balance, 0 ether);
        vm.prank(entryPoint);
        w.execute(bob, 1 ether, '');
        assertEq(bob.balance, 1 ether);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testExecuteERC20Transfer() public payable {
        vm.prank(entryPoint);
        w.execute(
            address(erc20), 0, abi.encodeWithSelector(MockERC20.transfer.selector, alice, 100 ether)
        );
    }

    function testExecuteERC20TransferWarm() public payable {
        vm.prank(entryPoint);
        w.execute(
            address(erc20), 0, abi.encodeWithSelector(MockERC20.transfer.selector, bob, 100 ether)
        );
    }

    function testExecuteERC20TransferAndCheckResult() public payable {
        assertEq(erc20.balanceOf(bob), 100 ether);
        vm.prank(entryPoint);
        w.execute(
            address(erc20), 0, abi.encodeWithSelector(MockERC20.transfer.selector, bob, 100 ether)
        );
        assertEq(erc20.balanceOf(bob), 200 ether);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testExecuteERC721Transfer() public payable {
        vm.prank(entryPoint);
        w.execute(
            address(erc721),
            0,
            abi.encodeWithSelector(MockERC721.transferFrom.selector, address(w), bob, 1)
        );
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testExecuteRevertDoesNotPayETH() public payable {
        uint balanceBefore = address(w).balance;
        MockRevertingContractForCalls c = new MockRevertingContractForCalls();
        vm.prank(entryPoint);
        // Foo call.
        w.execute(
            address(c), 1 ether, abi.encodeWithSelector(MockRevertingContractForCalls.foo.selector)
        );
        assertEq(address(w).balance, balanceBefore);
        // Garbage call.
        vm.prank(entryPoint);
        w.execute(address(c), 1 ether, abi.encodeWithSelector(0xdeadbeef));
        assertEq(address(w).balance, balanceBefore);
        // Ok call.
        vm.prank(entryPoint);
        w.execute(
            address(c), 1 ether, abi.encodeWithSelector(MockRevertingContractForCalls.ok.selector)
        );
        assertEq(address(w).balance, balanceBefore - 1 ether);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testIsValidSignature() public payable {
        bytes32 hash = keccak256(abi.encodePacked('foo()'));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, toEthSignedMessageHash(hash));
        // ABI encode hash and sig as expected by isValidSignature() / eip-1271.
        bytes memory data = abi.encodeWithSelector(0x1626ba7e, hash, abi.encode(v, r, s));
        (, bytes memory ret) = address(w).staticcall(data);

        bytes4 selector; // Slice selector return.
        assembly {
            selector := mload(add(ret, 0x20))
        }

        assert(selector == 0x1626ba7e); // Check match.
    }

    /*function testIsValidSignatureFromContract() public payable {
        bytes32 hash = keccak256(abi.encodePacked('foo()'));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, toEthSignedMessageHash(hash));
        // ABI encode hash and sig as expected by isValidSignature() / eip-1271.
        bytes memory data = abi.encodeWithSelector(0x1626ba7e, hash, abi.encode(v, r, s));
        (, bytes memory ret) = address(contractWallet).staticcall(data);

        bytes4 selector; // Slice selector return.
        assembly {
            selector := mload(add(ret, 0x20))
        }

        assert(selector == 0x1626ba7e); // Check match.
    }*/

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

    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32 result) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x20, hash) // Store into scratch space for keccak256.
            mstore(0x00, '\x00\x00\x00\x00\x19Ethereum Signed Message:\n32') // 28 bytes.
            result := keccak256(0x04, 0x3c) // `32 * 2 - (32 - 28) = 60 = 0x3c`.
        }
    }

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
        userOp.signature =
            sign(pK, toEthSignedMessageHash(IEntryPoint(entryPoint).getUserOpHash(userOp)));
    }

    enum Type {
        Address,
        Uint256,
        Uint8,
        Bytes32,
        Bytes,
        String
    }

    struct Param {
        Type pType;
        uint pSlot;
        bytes value;
    }

    struct Permit {
        address target;
        bytes4 selector;
        uint32 validAfter;
        uint32 validUntil;
        uint maxValue;
        Param[] params;
    }

    function createUserOpPermission(uint pK)
        internal
        view
        returns (Wallet.UserOperation memory userOp)
    {
        userOp.sender = address(w);
        uint16 validAfter = uint16(block.timestamp);
        uint16 validUntil = uint16(block.timestamp + 1000);

        // Make sure to define the sizes of each field

        // Packing data: Ensure no overlapping of bits by shifting adequately
        uint192 packedData = uint160(bob);
        console.log('packedData', packedData);
        userOp.nonce = IEntryPoint(entryPoint).getNonce(userOp.sender, packedData); // Put Bob as Sig Aggregator.

        // Extract key by right-shifting 64 bits
        uint key = userOp.nonce >> 64;

        // Unpacking data
        address extractedBob = address(uint160(key));
        // uint16 extractedValidUntil = uint16((packedData >> validAfterSize) & ((1 << validUntilSize) - 1));
        // uint16 extractedValidAfter = uint16(packedData & ((1 << validAfterSize) - 1));

        console.log('nonce', userOp.nonce);
        console.log('key', key);
        console.log('bob 1', bob);
        console.log('bob 2', extractedBob);
        // console.log('extractedValidUntil', extractedValidUntil);
        // console.log('extractedValidAfter', extractedValidAfter);

        userOp.initCode;
        // Build Dummy Permit.
        Param[] memory nullParam = new Param[](1);
        nullParam[0].pType = Type.Address;
        nullParam[0].pSlot = 0;
        nullParam[0].value = abi.encode(address(0));
        userOp.callData = abi.encodeWithSignature(
            'execute(address,uint,bytes)',
            bob,
            0,
            abi.encodeWithSignature(
                'validateUserPermit(bytes32,Permit)',
                bytes32(userOp.nonce),
                Permit(
                    address(erc20),
                    MockERC20.transfer.selector,
                    0,
                    type(uint32).max,
                    0.5 ether,
                    nullParam
                )
            )
        );
        // Leave rest Null.
        userOp.callGasLimit;
        userOp.verificationGasLimit;
        userOp.preVerificationGas;
        userOp.maxFeePerGas;
        userOp.maxPriorityFeePerGas;
        userOp.paymasterAndData;
        bytes32 hash = toEthSignedMessageHash(bytes32(key));

        userOp.signature = sign(pK, hash);
    }

    /*function validateUserPermit(bytes32 permitHash, bytes signature,Permit permit) {
            // create permitHash from Permit 
            // check permitHash === permitHashCreatedOnTheContract
            // ecrecover owner from signed permit 
            // if owner and permit is valid
            // check specific permit params
            // is between timestamp validUntil validAfter 
            // call.to === permit.target
            // call.value <= permit.maxValue
            // if call permitted - 
            // execute call 
        }*/

    function testValidateUserOp() public payable {
        // Success case.
        Wallet.UserOperation memory userOp = createUserOp(aliceKey, 0);
        bytes32 userOpHash = IEntryPoint(entryPoint).getUserOpHash(userOp);

        vm.prank(entryPoint); // Call as EP and check valid.
        assertEq(w.validateUserOp(userOp, userOpHash, 0), 0); // Return `0` for valid.
    }

    function testValidateUserOpPermission() public payable {
        // Success case.
        Wallet.UserOperation memory userOp = createUserOpPermission(aliceKey);
        bytes32 userOpHash = IEntryPoint(entryPoint).getUserOpHash(userOp);

        vm.prank(entryPoint); // Call as EP and check valid.
        assertEq(w.validateUserOp(userOp, userOpHash, 0), uint(uint160(bob))); // Return `bobHash` for valid.
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
        return abi.encode(v, r, s);
    }
}

interface IEntryPoint {
    function getUserOpHash(Wallet.UserOperation calldata userOp) external view returns (bytes32);
    function handleOps(Wallet.UserOperation[] calldata ops, address payable beneficiary) external;
    function getNonce(address sender, uint192 key) external view returns (uint nonce);
}

contract MockRevertingContractForCalls {
    function foo() public payable {
        revert('foo');
    }

    function ok() public payable returns (string memory) {
        return 'ok';
    }
}
