// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import {Wallet, WalletFactory} from "../src/WalletFactory.sol";
import "@forge/Test.sol";

contract WalletFactoryTest is Test {
    address constant owner = address(0xa);

    WalletFactory immutable wf = new WalletFactory();

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function setUp() public payable {}

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testDeploy() public payable {
        wf.deploy(owner);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testFailDuplicateDeploy() public payable {
        wf.deploy(owner);
        wf.deploy(owner);
    }
}
