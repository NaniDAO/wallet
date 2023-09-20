// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import {Wallet, WalletFactory} from "../src/WalletFactory.sol";
import "@forge/Test.sol";

contract WalletFactoryTest is Test {
    address immutable owner = address(0xa);

    WalletFactory immutable wf = new WalletFactory();

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function setUp() public payable {}

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testDeploy() public payable {
        wf.deploy(owner);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    /*function testDetermine() public {
        (address determined, bool deployed) = wf.determine(owner);
        assertFalse(deployed, "Should not be deployed yet");
        Wallet wallet = wf.deploy(owner);
        assertEq(address(wallet), determined, "Deployed and determined should match");
        (, deployed) = wf.determine(owner);
        assertTrue(deployed, "Should be deployed now");
    }*/

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testFailDuplicateDeploy() public payable {
        wf.deploy(owner);
        wf.deploy(owner);
    }
}
