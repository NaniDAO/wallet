// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import {EIP712} from '@solady/src/utils/EIP712.sol';
import '@forge/Test.sol';

import {Wallet} from '../src/Wallet.sol';

enum TYPE
// uint<M>: unsigned integer type of M bits, 0 < M <= 256, M % 8 == 0
{
    UINT,
    // int<M>: two’s complement signed integer type of M bits, 0 < M <= 256, M % 8 == 0.
    INT,
    // equivalent to uint160, except for the assumed interpretation and language typing. For computing the function selector, address is used.
    ADDRESS,
    // equivalent to uint8 restricted to the values 0 and 1. For computing the function selector, bool is used.
    BOOL,
    // bytes<M>: binary type of M bytes, 0 < M <= 32
    // bytes: dynamic sized byte sequence
    BYTES,
    // string: dynamic sized unicode string assumed to be UTF-8 encoded.
    STRING
}
// <type>[]: a variable-length array of elements of the given type.

// (T1,T2,...,Tn): tuple consisting of the types T1, …, Tn, n >= 0

struct Param {
    TYPE _type;
    uint8 offset;
    bytes bounds;
}

struct Slip {
    address[] targets;
    uint maxValue;
    bytes4 selector;
    Param[] arguments;
    string data;
    uint uses;
    uint validUntil;
    uint validAfter;
}

struct Call {
    address to;
    uint value;
    bytes data;
}

/**
 * @title Permissions
 * @dev Permissions contract
 */
contract Permissions is EIP712 {
    mapping(bytes32 slipHash => uint uses) public slipUses;

    function _domainNameAndVersion()
        internal
        pure
        override
        returns (string memory name, string memory version)
    {
        name = 'Permissions';
        version = '1';
    }

    function checkPermission(Wallet wallet, bytes memory sig, Slip memory slip, Call calldata call)
        public
        returns (bool)
    {
        require(slip.targets.length != 0, 'Permissions: no targets');
        require(slip.uses != 0, 'Permissions: no uses');
        require(slip.validAfter != 0, 'Permissions: no validAfter');
        require(slip.validUntil != 0, 'Permissions: no validUntil');
        require(
            slip.validAfter < slip.validUntil,
            'Permissions: validAfter must be less than validUntil'
        );

        bytes32 slipHash = getSlipHash(wallet, slip);
        // check if the slip is authorized
        bytes4 magicValue = wallet.isValidSignature(slipHash, sig);
        if (magicValue != 0x1626ba7e) return false;
        // check if slip is used
        if (slipUses[slipHash] >= slip.uses) return false;
        // increment slip use count
        slipUses[slipHash]++;

        // check if the slip is within time bounds
        if (slip.validAfter > block.timestamp || slip.validUntil < block.timestamp) return false;
        // check if call target is authorized
        for (uint i = 0; i < slip.targets.length; i++) {
            if (slip.targets[i] == call.to) break;
            if (i == slip.targets.length - 1) return false;
        }

        // check if the call is within value bounds
        if (call.value > slip.maxValue) return false;

        // check selector
        if (slip.selector.length != 0) {
            if (bytes4(call.data[:4]) != slip.selector) return false;

            // check if the call is within data bounds
            for (uint i = 0; i < slip.arguments.length; i++) {
                Param memory param = slip.arguments[i];
                
                if (param._type == TYPE.UINT) {
                    bytes memory data = call.data[param.offset:4];
                    uint max = abi.decode(param.bounds, (uint));
                    uint value = abi.decode(call.data[param.offset:], (uint));
                    if (value > max) return false;
                } 
                // else if (param._type == TYPE.INT) {
                //     int max = abi.decode(param.bounds, (int));
                //     int value = abi.decode(call.data[param.offset:], (int));

                //     if (value > max) return false;
                // } else if (param._type == TYPE.ADDRESS) {
                //     address bound = abi.decode(param.bounds, (address));
                //     address value = abi.decode(call.data[param.offset:], (address));

                //     if (bound != value) return false;
                // } else if (param._type == TYPE.BOOL) {
                //     bool bound = abi.decode(param.bounds, (bool));
                //     bool value = abi.decode(call.data[param.offset:], (bool));

                //     if (bound != value) return false;
                // } else if (param._type == TYPE.BYTES) {
                //     bytes memory bound = abi.decode(param.bounds, (bytes));
                //     bytes memory value = abi.decode(call.data[param.offset:], (bytes));

                //     if (bound != value) return false;
                // } else if (param._type == TYPE.STRING) {
                //     string memory bound = abi.decode(param.bounds, (string));
                //     string memory value = abi.decode(call.data[param.offset:], (string));

                //     if (bound != value) return false;
                // }
            }
        }

        return true;
    }

    function getSlipHash(Wallet wallet, Slip memory slip) public view returns (bytes32) {
        return _hashTypedData(keccak256(abi.encode(wallet, slip)));
    }
}
