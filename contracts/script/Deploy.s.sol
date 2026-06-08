// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {IdentityRegistry} from "../src/IdentityRegistry.sol";
import {ReputationRegistry} from "../src/ReputationRegistry.sol";
import {JobEscrow} from "../src/JobEscrow.sol";

/// @notice Deploy the identity + reputation registries and the job escrow to Arc testnet.
/// @dev    Run with:
///         forge script script/Deploy.s.sol:Deploy \
///           --rpc-url arc_testnet --broadcast \
///           --private-key $ARC_PRIVATE_KEY --legacy=false
///         Arc uses EIP-1559 (type 2); do NOT pass --legacy.
contract Deploy is Script {
    function run() external {
        vm.startBroadcast();

        IdentityRegistry identity = new IdentityRegistry();
        ReputationRegistry reputation = new ReputationRegistry(address(identity));
        JobEscrow escrow = new JobEscrow(address(identity));

        vm.stopBroadcast();

        console.log("IdentityRegistry  :", address(identity));
        console.log("ReputationRegistry:", address(reputation));
        console.log("JobEscrow         :", address(escrow));
    }
}
