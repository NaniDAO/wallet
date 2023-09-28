// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import {Wallet, WalletFactory} from '../src/WalletFactory.sol';
import '@forge/Test.sol';

contract WalletFactoryTest is Test {
    bytes32 constant owner = bytes32(uint(uint160(address(0xa)))); // Hashed.

    WalletFactory immutable wf = new WalletFactory(); // Factory.

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function setUp() public payable {}

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testDeploy() public payable {
        wf.deploy(owner); // Put in hashed owner.
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testFailDuplicateDeploy() public payable {
        wf.deploy(owner); // Do once.
        wf.deploy(owner); // Fail once.
    }
}
