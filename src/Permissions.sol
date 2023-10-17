// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import {ECDSA} from '@solady/src/utils/ECDSA.sol';
import {EIP712} from '@solady/src/utils/EIP712.sol';
import {ERC4337} from '@solady/test/utils/mocks/MockERC4337.sol';
import {SignatureCheckerLib} from '@solady/src/utils/SignatureCheckerLib.sol';
import {LibSort} from '@solady/src/utils/LibSort.sol';

import '@forge/Test.sol';

enum TYPE
// uint<M>: unsigned integer type of M bits, 0 < M <= 256, M % 8 == 0
{
    UINT,
    UINT8,
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
    uint length;
}

struct Slip {
    address[] targets;
    uint maxValue;
    bytes4 selector;
    Param[] arguments;
    uint192 uses;
    uint32 validAfter;
    uint32 validUntil;
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

    function checkPermission(
        ERC4337 wallet,
        bytes calldata sig,
        Slip calldata slip,
        Call calldata call
    ) public returns (bool) {
        require(slip.targets.length != 0, 'Permissions: no targets');
        require(slip.uses != 0, 'Permissions: no uses');
        require(
            slip.validAfter <= slip.validUntil,
            'Permissions: validAfter must be less than or equal to validUntil'
        );

        bytes32 slipHash = getSlipHash(wallet, slip);
        // check if the slip is authorized
        if (!SignatureCheckerLib.isValidERC1271SignatureNowCalldata(address(wallet), slipHash, sig))
        {
            return false;
        }

        // check if slip is used up after increment
        unchecked {
            if (slip.uses == slipUses[slipHash]++) return false;
        }

        // check if slip is within valid time bounds or infinite
        if ((slip.validAfter != 0 && block.timestamp < slip.validAfter) || 
            (slip.validUntil != 0 && block.timestamp > slip.validUntil)) return false;

        // check if call target is authorized
        unchecked {
            for (uint i; i < slip.targets.length; ++i) {
                if (slip.targets[i] == call.to) break;
                if (i == slip.targets.length - 1) return false;
            }
        }

        // check if the call is within value bounds
        if (call.value > slip.maxValue) return false;

        // check selector
        if (slip.selector.length != 0 && call.data.length != 0) {
            if (bytes4(call.data[:4]) != bytes4(slip.selector)) return false;

            // check if the call is within data bounds
            for (uint i; i < slip.arguments.length; i++) {
                Param calldata param = slip.arguments[i];

                if (param._type == TYPE.UINT) {
                    if (_validateUint(abi.decode(call.data[param.offset:param.offset + 32], (uint)), param.bounds)) break;
                    return false;
                } else if (param._type == TYPE.UINT8) {
                    console.log(i, 'param is uint8');
                    uint8[] memory allowed = new uint8[](param.bounds.length/32);
                    for (uint j; j < param.bounds.length / 32; j++) {
                        allowed[j] = abi.decode(param.bounds[j * 32:j * 32 + 32], (uint8));
                        console.log('allowed', uint256(allowed[j]));
                    }
                    // (uint8[] memory allowed) = abi.decode(param.bounds[0:32], (uint8[]));
                    // console2.log(uint256(allowed));
                    uint8 value = abi.decode(call.data[param.offset:param.offset + 32], (uint8));
                    console.log(uint256(value));
                    for (uint j; j < allowed.length; j++) {
                        if (allowed[j] == value) break;
                        if (j == allowed.length - 1) return false;
                    }
                } else if (param._type == TYPE.INT) {
                    console.log(i, 'param is int');
                    (int min, int max) = abi.decode(param.bounds, (int, int));
                    int value = abi.decode(call.data[param.offset:param.offset + 32], (int));
                    if (value > max || value < min) return false;
                } else if (param._type == TYPE.ADDRESS) {
                    console.log(i, 'param is address');
                    address value = abi.decode(call.data[param.offset:param.offset + 32], (address));
                    console.logAddress(value);
                    bool valid = _validateAddress(value, param.bounds);
                    if (valid) break;
                    return false;
                } else if (param._type == TYPE.BOOL) {
                    console.log(i, 'param is bool');
                    bool bound = abi.decode(param.bounds, (bool));
                    bytes calldata data = bytes(call.data[param.offset:param.offset + 32]);
                    bool value = abi.decode(data, (bool));
                    if (bound != value) return false;
                }
                // else if (param._type == TYPE.BYTES) {
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

    function getSlipHash(ERC4337 wallet, Slip calldata slip) public view returns (bytes32) {
        return _hashTypedData(keccak256(abi.encode(wallet, slip)));
    }

    function _validateUint(uint value, bytes memory bounds)
        internal
        pure
        returns (bool found)
    {
        (uint min, uint max) = abi.decode(bounds, (uint, uint));
        return value >= min && value <= max;
    }

    function _validateEnum(uint256 value, bytes memory bounds) internal pure returns (bool found) {
        (uint256[] memory bound) = abi.decode(bounds, (uint256[]));
        LibSort.sort(bound);
        (found,) = LibSort.searchSorted(bound, value);
        return found;
    }

    function _validateAddress(address value, bytes memory bounds)
        internal
        view
        returns (bool found)
    {
        (address[] memory bound) = abi.decode(bounds, (address[]));
        LibSort.sort(bound);
        (found,) = LibSort.searchSorted(bound, value);
        return found;
    }
}
