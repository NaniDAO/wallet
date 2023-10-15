// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import '@forge/Test.sol';
import {Permissions, Slip, Call, Param} from '../src/Permissions.sol';
import {Wallet} from '../src/Wallet.sol';

contract PermissionsTest is Test {
    Permissions permissions;
    Wallet wallet;

    address alice;
    bytes32 aliceHash;
    uint aliceKey;

    function setUp() public payable {
        (alice, aliceKey) = makeAddrAndKey('alice');

        aliceHash = bytes32(uint(uint160(alice)));

        permissions = new Permissions();
        wallet = new Wallet(aliceHash);
    }

    function testCheckPermission() public {
        address[] memory targets = new address[](1);
        targets[0] = address(this);
        Slip memory slip = createSlip(targets, 1, block.timestamp, block.timestamp + 1000);
        Call memory call = Call({to: address(this), value: 0, data: ''});

        bytes32 slipHash = permissions.getSlipHash(wallet, slip);
        bytes memory sig = sign(aliceKey, slipHash);

        permissions.checkPermission(wallet, sig, slip, call);
    }

    function createSlip(address[] memory targets, uint uses, uint validAfter, uint validUntil)
        public
        pure
        returns (Slip memory slip)
    {
        return Slip({
            targets: targets,
            maxValue: 0,
            selector: bytes4(keccak256('testCheckPermission()')),
            arguments: new Param[](0),
            data: '',
            uses: uses,
            validUntil: validUntil,
            validAfter: validAfter
        });
    }

    function sign(uint pK, bytes32 hash) internal pure returns (bytes memory) {
        // Helper.
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pK, hash);
        return abi.encode(v, r, s);
    }
}
