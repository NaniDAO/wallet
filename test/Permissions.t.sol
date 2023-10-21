// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import '@forge/Test.sol';
import '@solady/test/utils/TestPlus.sol';
import {LibClone} from '@solady/src/utils/LibClone.sol';
import {SignatureCheckerLib} from '@solady/src/utils/SignatureCheckerLib.sol';

import {ERC4337, MockERC4337} from '@solady/test/utils/mocks/MockERC4337.sol';
import {MockERC20} from '@solady/test/utils/mocks/MockERC20.sol';
import {LibSort} from '@solady/src/utils/LibSort.sol';

import {Permissions, Slip, Call, Param, TYPE, Span} from '../src/Permissions.sol';
import {Wallet} from '../src/Wallet.sol';

contract PermissionsTester {
    enum State {
        PENDING,
        APPROVED,
        REJECTED,
        CANCELLED,
        EXECUTED,
        EXPIRED,
        FAILED
    }

    struct StaticTuple {
        address a;
        uint b;
        bool c;
    }

    constructor() {}

    function getRandomState() public view returns (uint[] memory) {
        uint[] memory randomStates = new uint256[](7);
        for (uint i = 0; i < 7; i++) {
            randomStates[i] = uint(State(i));
        }
        return randomStates;
    }

    function dataUint(uint data) public pure returns (uint) {
        return data;
    }

    function dataInt(int data) public pure returns (int) {
        return data;
    }

    function dataAddress(address data) public pure returns (address) {
        return data;
    }

    function dataValue() public payable returns (uint) {
        return msg.value;
    }

    function dataBool(bool data) public pure returns (bool) {
        return data;
    }
}

contract PermissionsTest is Test, TestPlus {
    Permissions permissions;
    MockERC4337 wallet;

    address alice;
    uint aliceKey;

    address bob;
    uint bobKey;

    function setUp() public payable {
        (alice, aliceKey) = makeAddrAndKey('alice');

        permissions = new Permissions();

        address accountImplementation = address(new MockERC4337());
        wallet = MockERC4337(payable(LibClone.deployERC1967(accountImplementation)));
        wallet.initialize(alice);
    }

    function testValuePermission(uint value, uint maxValue) public {
        vm.assume(value <= type(uint128).max);
        vm.assume(maxValue <= type(uint128).max);
        address[] memory targets = getTargets(0, alice);
        console.log(targets[0]);
        Span[] memory spans = new Span[](1);
        spans[0] = Span({validAfter: uint32(block.timestamp), validUntil: uint32(block.timestamp + 100000)});
        Slip memory slip = createSlip(
            targets,
            maxValue,
            bytes4(0),
            new Param[](0),
            spans
        );
        Call memory call = Call({to: alice, value: value, data: ''});
        bytes32 slipHash = permissions.getSlipHash(wallet, slip);

        bytes memory sig = sign(aliceKey, SignatureCheckerLib.toEthSignedMessageHash(slipHash));
        bool assertion = value <= slip.maxValue;
        assertEq(permissions.checkPermission(wallet, sig, slip, call), assertion);
    }

    // function testTimePermissions(Span[] spans) public {
    //     vm.assume(spans.length != 0);
    //     vm.assume(spans.length <= type(uint8).max);
    //     require(spans.length != 0);
    //     require(spans.length <= type(uint8).max);

    //     address[] memory targets = getTargets(0, alice);
    //     Slip memory slip = createSlip(
    //         targets, 0, bytes4(0), new Param[](0), 1, 0
    //     );
    //     Call memory call = Call({to: alice, value: 0, data: ''});
    //     bytes32 slipHash = permissions.getSlipHash(wallet, slip);

    //     bytes memory sig = sign(aliceKey, SignatureCheckerLib.toEthSignedMessageHash(slipHash));
    //     bool assertion = 
    //     assertEq(permissions.checkPermission(wallet, sig, slip, call), assertion);
    // }

    function testUintPermission(uint val, uint min, uint max) public {
        vm.assume(min < max);
        vm.assume(val <= type(uint).max);
        vm.assume(min <= type(uint).max);
        vm.assume(max <= type(uint).max);
        require(min <= max);

        bool assertion = !(val < min || val > max);

        PermissionsTester tester = new PermissionsTester();

        address[] memory targets = getTargets(0, alice);
        Param[] memory arguments = new Param[](1);
        arguments[0] = Param({_type: TYPE.UINT, offset: 4, bounds: abi.encode(min, max), length: 0});
                Span[] memory spans = new Span[](1);
        spans[0] = Span({validAfter: uint32(block.timestamp), validUntil: uint32(block.timestamp + 100000)});
        Slip memory slip = createSlip(
            targets,
            0,
            tester.dataUint.selector,
            arguments,
            spans
        );

        Call memory call = Call({to: alice, value: 0, data: abi.encodeCall(tester.dataUint, (val))});

        bytes32 slipHash = permissions.getSlipHash(wallet, slip);
        bytes memory sig = sign(aliceKey, SignatureCheckerLib.toEthSignedMessageHash(slipHash));

        assertEq(permissions.checkPermission(wallet, sig, slip, call), assertion);
    }

    function testEnumPermission(uint value) public {
        value = bound(value, 0, uint(PermissionsTester.State.FAILED));
        require(value >= 0 && value <= uint(PermissionsTester.State.FAILED));

        PermissionsTester tester = new PermissionsTester();
        uint[] memory bounds = tester.getRandomState();

        LibSort.sort(bounds);
        (bool assertion, uint index) = LibSort.searchSorted(bounds, value);

        address[] memory targets = getTargets(0, alice);
        Param[] memory arguments = new Param[](1);
        arguments[0] = Param({_type: TYPE.UINT8, offset: 4, bounds: abi.encode(bounds), length: 0});
        Span[] memory spans = new Span[](1);
        spans[0] = Span({validAfter: uint32(block.timestamp), validUntil: uint32(block.timestamp + 100000)});
        Slip memory slip = createSlip(
            targets,
            0,
            tester.dataUint.selector,
            arguments,
            spans
        );

        Call memory call =
            Call({to: alice, value: 0, data: abi.encodeCall(tester.dataUint, (uint(value)))});

        bytes32 slipHash = permissions.getSlipHash(wallet, slip);

        bytes memory sig = sign(aliceKey, SignatureCheckerLib.toEthSignedMessageHash(slipHash));
        assertEq(permissions.checkPermission(wallet, sig, slip, call), assertion);
    }

    // function testStaticTuple(PermissionsTester.StaticTuple memory s) public {
    //     PermissionsTester tester = new PermissionsTester();
    //     address[] memory targets = getTargets(0, alice);

    //     Param[] memory arguments = new Param[](1);
    //      Param[] memory bounds = new Param[](s.length);
    //     arguments[0] = Param({
    //         _type: TYPE.TUPLE,
    //         offset: 4,
    //         bounds: abi.encode(),
    //         length: 3
    //     });

    //     Slip memory slip = createSlip(
    //         targets,
    //         0,
    //         tester.dataUint.selector,
    //         arguments,
    //         5,
    //         uint32(block.timestamp),
    //         uint32(block.timestamp + 100000)
    //     );

    //     Call memory call =
    //         Call({to: alice, value: 0, data: abi.encodeCall(tester.dataUint, (uint(1)))});

    //     bytes32 slipHash = permissions.getSlipHash(wallet, slip);

    //     bytes memory sig = sign(aliceKey, SignatureCheckerLib.toEthSignedMessageHash(slipHash));
    //     assertEq(permissions.checkPermission(wallet, sig, slip, call), true);
    // }

    // function testCheckTransferPermission() public {
    //     MockERC20 token = new MockERC20("Token", "TKN", 18);

    //     address[] memory targets = new address[](1);
    //     targets[0] = address(token);

    //     Param[] memory arguments = new Param[](2);
    //     arguments[0] = Param({
    //         _type: TYPE.ADDRESS,
    //         offset: 4,
    //         bounds: abi.encodePacked(address(this), alice),
    //         length: 0
    //     });
    //     arguments[1] = Param({
    //         _type: TYPE.UINT,
    //         offset: 36,
    //         bounds: abi.encodePacked(uint(2 ether)),
    //         length: 0
    //     });

    //     Slip memory slip = createSlip(
    //         targets,
    //         0,
    //         token.transfer.selector,
    //         arguments,
    //         5,
    //         uint32(block.timestamp),
    //         uint32(block.timestamp + 100000)
    //     );
    //     Call memory call = Call({
    //         to: address(token),
    //         value: 0,
    //         data: abi.encodeWithSelector(token.transfer.selector, address(this), 1.5 ether)
    //     });

    //     bytes32 slipHash = permissions.getSlipHash(wallet, slip);
    //     bytes memory sig = sign(aliceKey, SignatureCheckerLib.toEthSignedMessageHash(slipHash));

    //     assertTrue(permissions.checkPermission(wallet, sig, slip, call));
    // }

    // function testFailCheckTransferPermission() public {
    //     MockERC20 token = new MockERC20("Token", "TKN", 18);

    //     address[] memory targets = new address[](1);
    //     targets[0] = address(token);

    //     Param[] memory arguments = new Param[](2);
    //     arguments[0] = Param({
    //         _type: TYPE.ADDRESS,
    //         offset: 4,
    //         bounds: abi.encodePacked(address(this), alice),
    //         length: 0
    //     });
    //     arguments[1] = Param({
    //         _type: TYPE.UINT,
    //         offset: 36,
    //         bounds: abi.encodePacked(uint(2 ether)),
    //         length: 0
    //     });

    //     Slip memory slip = createSlip(
    //         targets,
    //         0,
    //         token.transfer.selector,
    //         arguments,
    //         5,
    //         uint32(block.timestamp),
    //         uint32(block.timestamp + 100000)
    //     );
    //     Call memory call = Call({
    //         to: bob,
    //         value: 0,
    //         data: abi.encodeWithSelector(token.transfer.selector, address(this), 1.5 ether)
    //     });

    //     bytes32 slipHash = permissions.getSlipHash(wallet, slip);
    //     bytes memory sig = sign(aliceKey, SignatureCheckerLib.toEthSignedMessageHash(slipHash));

    //     assertTrue(permissions.checkPermission(wallet, sig, slip, call));
    // }

    function testBoolPermissions(bool value, bool bound) public {
        PermissionsTester tester = new PermissionsTester();

        address[] memory targets = getTargets(0, alice);

        Param[] memory arguments = new Param[](1);
        arguments[0] = Param({_type: TYPE.BOOL, offset: 4, bounds: abi.encode(bound), length: 0});
        Span[] memory spans = new Span[](1);
        spans[0] = Span({validAfter: uint32(block.timestamp), validUntil: uint32(block.timestamp + 100000)});
        Slip memory slip = createSlip(
            targets,
            0,
            tester.dataBool.selector,
            arguments,
            spans
        );
        Call memory call =
            Call({to: alice, value: 0, data: abi.encodeCall(tester.dataBool, (value))});

        bytes32 slipHash = permissions.getSlipHash(wallet, slip);
        bytes memory sig = sign(aliceKey, SignatureCheckerLib.toEthSignedMessageHash(slipHash));

        assertEq(permissions.checkPermission(wallet, sig, slip, call), value == bound);
    }

    function testAddressPermission(address value, address[] memory bounds) public {
        vm.assume(bounds.length != 0);
        vm.assume(bounds.length <= type(uint8).max);
        require(bounds.length != 0);
        require(bounds.length <= type(uint8).max);

        LibSort.sort(bounds);
        (bool assertion, uint index) = LibSort.searchSorted(bounds, value);
        console.log('found', assertion);
        console.log('index', index);
        console.log('found value', bounds[index]);

        PermissionsTester tester = new PermissionsTester();
        address[] memory targets = getTargets(0, alice);
        Param[] memory arguments = new Param[](1);
        arguments[0] =
            Param({_type: TYPE.ADDRESS, offset: 4, bounds: abi.encode(bounds), length: 0});

                Span[] memory spans = new Span[](1);
        spans[0] = Span({validAfter: uint32(block.timestamp), validUntil: uint32(block.timestamp + 100000)});
        Slip memory slip = createSlip(
            targets,
            0,
            tester.dataAddress.selector,
            arguments,
            spans
        );

        Call memory call =
            Call({to: alice, value: 0, data: abi.encodeCall(tester.dataAddress, (value))});

        bytes32 slipHash = permissions.getSlipHash(wallet, slip);

        bytes memory sig = sign(aliceKey, SignatureCheckerLib.toEthSignedMessageHash(slipHash));
        console.log('length', bounds.length);
        assertEq(permissions.checkPermission(wallet, sig, slip, call), assertion);
    }

    function testIntPermission(int a, int min, int max) public {
        // prevent overflows;
        a = bound(a, type(int).min, type(int).max);
        min = bound(min, type(int).min, type(int).max);
        max = bound(max, type(int).min, type(int).max);

        vm.assume(min < max);
        vm.assume(a <= type(int).max && a >= type(int).min);
        vm.assume(min <= type(int).max && min >= type(int).min);
        vm.assume(max <= type(int).max && max >= type(int).min);
        require(min <= max);

        bool assertion = !(a > max || a < min);

        PermissionsTester tester = new PermissionsTester();

        address[] memory targets = new address[](1);
        targets[0] = address(tester);

        Param[] memory arguments = new Param[](1);
        arguments[0] = Param({_type: TYPE.INT, offset: 4, bounds: abi.encode(min, max), length: 0});
        
        Span[] memory spans = new Span[](1);
        spans[0] = Span({validAfter: uint32(block.timestamp), validUntil: uint32(block.timestamp + 100000)});
        Slip memory slip = createSlip(
            targets,
            0,
            tester.dataInt.selector,
            arguments,
            spans
        );

        Call memory call =
            Call({to: address(tester), value: 0, data: abi.encodeCall(tester.dataInt, (a))});

        bytes32 slipHash = permissions.getSlipHash(wallet, slip);
        bytes memory sig = sign(aliceKey, SignatureCheckerLib.toEthSignedMessageHash(slipHash));

        assert(permissions.checkPermission(wallet, sig, slip, call) == assertion);
    }

    function createSlip(
        address[] memory targets,
        uint maxValue,
        bytes4 selector,
        Param[] memory arguments,
        Span[] memory spans
    ) public pure returns (Slip memory slip) {
        return Slip({
            targets: targets,
            maxValue: maxValue,
            selector: selector,
            arguments: arguments,
            spans: spans
        });
    }

    function getTargets(uint8 length, address include)
        internal
        returns (address[] memory targets)
    {
        bool toInclude = include != address(0);
        targets = new address[](toInclude ? length + 1 : length);

        if (length != 0) {
            for (uint8 i = 0; i < length - 1; i++) {
                targets[i] = _randomAddress();
            }
        }

        if (toInclude) {
            targets[length] = include;
        }
    }

    function sign(uint pK, bytes32 hash) internal pure returns (bytes memory) {
        // Helper.
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pK, hash);
        return abi.encodePacked(r, s, v);
    }
}
