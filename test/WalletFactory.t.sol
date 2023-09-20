// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import "../src/WalletFactory.sol";
import "@forge/Test.sol";

contract WalletFactoryTest is Test {
    WalletFactory wf;

    address alice;

    address bob;

    function setUp() public payable {
        alice = makeAddr("alice");
        bob = makeAddr("bob");

        wf = new WalletFactory();
    }

    function testDeploy() public payable {
        wf.deploy(alice, bob);
        (address walletAddress, bool deployed) = wf.determine(alice, bob);
        assertTrue(deployed, "Wallet should be deployed");
    }

    function testDetermine() public {
        wf.deploy(alice, bob);
        (address walletAddress, bool deployed) = wf.determine(alice, bob);
        assertTrue(deployed, "Wallet should be deployed");
    }
}
