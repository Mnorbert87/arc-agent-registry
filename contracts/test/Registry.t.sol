// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {IdentityRegistry} from "../src/IdentityRegistry.sol";
import {ReputationRegistry} from "../src/ReputationRegistry.sol";

contract RegistryTest is Test {
    IdentityRegistry identity;
    ReputationRegistry reputation;

    // a deterministic agent-owner keypair
    uint256 agentPk = 0xA11CE;
    address agentOwner;
    address client = address(0xC11E27);

    function setUp() public {
        identity = new IdentityRegistry();
        reputation = new ReputationRegistry(address(identity));
        agentOwner = vm.addr(agentPk);
    }

    function _register() internal returns (uint256 agentId) {
        vm.prank(agentOwner);
        agentId = identity.register("https://alice.example/.well-known/agent-card.json");
    }

    function test_RegisterMintsSequentialIds() public {
        uint256 a = _register();
        assertEq(a, 1);
        assertEq(identity.ownerOf(a), agentOwner);
        assertEq(identity.agentCount(), 1);
        assertTrue(identity.exists(a));
        assertEq(identity.tokenURI(a), "https://alice.example/.well-known/agent-card.json");
    }

    function test_OnlyOwnerCanUpdate() public {
        uint256 a = _register();
        vm.prank(client);
        vm.expectRevert("not agent owner");
        identity.updateRegistration(a, "https://evil/card.json");

        vm.prank(agentOwner);
        identity.updateRegistration(a, "https://alice.example/card-v2.json");
        assertEq(identity.tokenURI(a), "https://alice.example/card-v2.json");
    }

    // secp256k1 group order
    uint256 constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    function _digest(uint256 agentId, address who, uint64 expiry, bytes32 nonce) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(reputation.FEEDBACK_AUTH_TYPEHASH(), agentId, who, expiry, nonce));
        return keccak256(abi.encodePacked("\x19\x01", reputation.DOMAIN_SEPARATOR(), structHash));
    }

    function _sign(uint256 agentId, address who, uint64 expiry, bytes32 nonce) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(agentPk, _digest(agentId, who, expiry, nonce));
        return abi.encodePacked(r, s, v);
    }

    function test_GiveFeedbackWithValidAuth() public {
        uint256 a = _register();
        uint64 expiry = uint64(block.timestamp + 3600);
        bytes32 nonce = keccak256("n1");
        bytes memory sig = _sign(a, client, expiry, nonce);

        vm.prank(client);
        reputation.giveFeedback(a, 90, bytes32("memory-search"), "", expiry, nonce, sig);

        (uint64 n, uint256 sum, uint256 avg) = reputation.getSummary(a);
        assertEq(n, 1);
        assertEq(sum, 90);
        assertEq(avg, 90);
    }

    function test_FeedbackRejectsWrongClient() public {
        uint256 a = _register();
        uint64 expiry = uint64(block.timestamp + 3600);
        bytes32 nonce = keccak256("n2");
        // auth is for `client`, but address(0xBAD) tries to use it
        bytes memory sig = _sign(a, client, expiry, nonce);

        vm.prank(address(0xBAD));
        vm.expectRevert("auth not signed by agent owner");
        reputation.giveFeedback(a, 50, 0, "", expiry, nonce, sig);
    }

    function test_FeedbackRejectsReplay() public {
        uint256 a = _register();
        uint64 expiry = uint64(block.timestamp + 3600);
        bytes32 nonce = keccak256("n3");
        bytes memory sig = _sign(a, client, expiry, nonce);

        vm.prank(client);
        reputation.giveFeedback(a, 80, 0, "", expiry, nonce, sig);

        vm.prank(client);
        vm.expectRevert("nonce used");
        reputation.giveFeedback(a, 80, 0, "", expiry, nonce, sig);
    }

    function test_FeedbackRejectsExpired() public {
        uint256 a = _register();
        uint64 expiry = uint64(block.timestamp + 10);
        bytes32 nonce = keccak256("n4");
        bytes memory sig = _sign(a, client, expiry, nonce);

        vm.warp(block.timestamp + 100);
        vm.prank(client);
        vm.expectRevert("auth expired");
        reputation.giveFeedback(a, 80, 0, "", expiry, nonce, sig);
    }

    function test_FeedbackRejectsScoreTooHigh() public {
        uint256 a = _register();
        uint64 expiry = uint64(block.timestamp + 3600);
        bytes32 nonce = keccak256("n5");
        bytes memory sig = _sign(a, client, expiry, nonce);

        vm.prank(client);
        vm.expectRevert("score > 100");
        reputation.giveFeedback(a, 101, 0, "", expiry, nonce, sig);
    }

    /// A forged signature with the same r but a flipped (high) s and toggled v recovers the
    /// same signer on raw ecrecover. The contract must reject it (EIP-2) so an attacker cannot
    /// mint a second distinct-but-valid signature from one the owner already issued.
    function test_FeedbackRejectsMalleableSignature() public {
        uint256 a = _register();
        uint64 expiry = uint64(block.timestamp + 3600);
        bytes32 nonce = keccak256("malleable");

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(agentPk, _digest(a, client, expiry, nonce));

        // produce the malleable counterpart: s' = n - s, v' = flipped
        bytes memory badSig = abi.encodePacked(r, bytes32(SECP256K1_N - uint256(s)), v == 27 ? uint8(28) : uint8(27));

        vm.prank(client);
        vm.expectRevert("bad sig s");
        reputation.giveFeedback(a, 90, 0, "", expiry, nonce, badSig);
    }

    /// An auth signed for agentId=A cannot be replayed against a different agentId=B,
    /// even when both share the same nonce.
    function test_FeedbackRejectsCrossAgentReplay() public {
        uint256 a = _register();
        // a second agent owned by someone else
        uint256 otherPk = 0xB0B;
        address otherOwner = vm.addr(otherPk);
        vm.prank(otherOwner);
        uint256 b = identity.register("https://b.example/card.json");

        uint64 expiry = uint64(block.timestamp + 3600);
        bytes32 nonce = keccak256("shared");
        bytes memory sigForA = _sign(a, client, expiry, nonce);

        // the agentId is bound into the signed struct, so reusing it on b fails recovery
        vm.prank(client);
        vm.expectRevert("auth not signed by agent owner");
        reputation.giveFeedback(b, 90, 0, "", expiry, nonce, sigForA);
    }

    function test_AverageAcrossMultiple() public {
        uint256 a = _register();
        uint8[3] memory scores = [uint8(100), 80, 60];
        for (uint256 i = 0; i < 3; i++) {
            uint64 expiry = uint64(block.timestamp + 3600);
            bytes32 nonce = keccak256(abi.encodePacked("multi", i));
            bytes memory sig = _sign(a, client, expiry, nonce);
            vm.prank(client);
            reputation.giveFeedback(a, scores[i], 0, "", expiry, nonce, sig);
        }
        (uint64 n,, uint256 avg) = reputation.getSummary(a);
        assertEq(n, 3);
        assertEq(avg, 80); // (100+80+60)/3
    }
}
