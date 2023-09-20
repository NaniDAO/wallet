// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import {Wallet, WalletFactory} from "../src/WalletFactory.sol";
import "@forge/Test.sol";

contract WalletFactoryTest is Test {
    address immutable owner = address(0xa);
    address constant entryPoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    WalletFactory immutable wf = new WalletFactory();

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function setUp() public payable {}

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testDeploy() public payable {
        wf.deploy(owner, entryPoint);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testDetermine() public {
        (address determined, bool deployed) = wf.determine(owner, entryPoint);
        assertFalse(deployed, "Should not be deployed yet");
        Wallet wallet = wf.deploy(owner, entryPoint);
        assertEq(address(wallet), determined, "Deployed and determined should match");
        (, deployed) = wf.determine(owner, entryPoint);
        assertTrue(deployed, "Should be deployed now");
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////

    function testFailDuplicateDeploy() public payable {
        wf.deploy(owner, entryPoint);
        wf.deploy(owner, entryPoint);
    }
}
