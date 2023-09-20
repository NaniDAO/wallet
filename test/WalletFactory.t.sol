// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import {Wallet, WalletFactory} from "../src/WalletFactory.sol";
import "@forge/Test.sol";

contract WalletFactoryTest is Test {
    address owner;
    address validator;

    WalletFactory wf;

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function setUp() public payable {
        owner = makeAddr("owner");
        validator = makeAddr("validator");
        wf = new WalletFactory();
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testDeploy() public payable {
        wf.deploy(owner, validator);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testDetermine() public {
        (address determined, bool deployed) = wf.determine(owner, validator);
        assertFalse(deployed, "Should not be deployed yet");
        Wallet wallet = wf.deploy(owner, validator);
        assertEq(address(wallet), determined, "Deployed and determined should match");
        (, deployed) = wf.determine(owner, validator);
        assertTrue(deployed, "Should be deployed now");
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testFailDuplicateDeploy() public payable {
        wf.deploy(owner, validator);
        wf.deploy(owner, validator);
    }
}
