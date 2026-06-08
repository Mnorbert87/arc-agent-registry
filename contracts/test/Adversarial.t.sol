// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {IdentityRegistry} from "../src/IdentityRegistry.sol";
import {ReputationRegistry} from "../src/ReputationRegistry.sol";
import "../src/JobEscrow.sol";

// ============================================================================
// Forge fresh adversarial pass (2026-06-08). Written independently of the
// original suite to attack each contract again from scratch. Every test here is
// an attempted exploit; a green run means the attack was repelled.
// ============================================================================

// --- attack token that re-enters an arbitrary escrow function on transfer ---
contract MultiReentrantToken {
    enum Target {
        None,
        Release,
        Claim,
        Refund
    }

    string public name = "Reentrant";
    uint8 public decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    JobEscrow public escrow;
    uint256 public targetJob;
    Target public mode;
    bool internal armed;
    bool public attempted;
    bool public reverted;

    function mint(address to, uint256 amt) external {
        balanceOf[to] += amt;
    }

    function approve(address spender, uint256 amt) external returns (bool) {
        allowance[msg.sender][spender] = amt;
        return true;
    }

    function arm(JobEscrow _e, uint256 _job, Target _mode) external {
        escrow = _e;
        targetJob = _job;
        mode = _mode;
        armed = true;
    }

    function _attack() internal {
        if (!armed) return;
        armed = false;
        attempted = true;
        if (mode == Target.Release) {
            try escrow.release(targetJob) {
                reverted = false;
            } catch {
                reverted = true;
            }
        } else if (mode == Target.Claim) {
            try escrow.claim(targetJob) {
                reverted = false;
            } catch {
                reverted = true;
            }
        } else if (mode == Target.Refund) {
            try escrow.refund(targetJob) {
                reverted = false;
            } catch {
                reverted = true;
            }
        }
    }

    function transfer(address to, uint256 amt) external returns (bool) {
        _attack();
        require(balanceOf[msg.sender] >= amt, "balance");
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt;
        return true;
    }

    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        _attack();
        require(balanceOf[from] >= amt, "balance");
        uint256 a = allowance[from][msg.sender];
        require(a >= amt, "allowance");
        if (a != type(uint256).max) allowance[from][msg.sender] = a - amt;
        balanceOf[from] -= amt;
        balanceOf[to] += amt;
        return true;
    }
}

contract MockUSDC2 {
    string public name = "Mock USDC";
    uint8 public decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amt) external {
        balanceOf[to] += amt;
    }

    function approve(address spender, uint256 amt) external returns (bool) {
        allowance[msg.sender][spender] = amt;
        return true;
    }

    function transfer(address to, uint256 amt) external returns (bool) {
        require(balanceOf[msg.sender] >= amt, "balance");
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt;
        return true;
    }

    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        require(balanceOf[from] >= amt, "balance");
        uint256 a = allowance[from][msg.sender];
        require(a >= amt, "allowance");
        if (a != type(uint256).max) allowance[from][msg.sender] = a - amt;
        balanceOf[from] -= amt;
        balanceOf[to] += amt;
        return true;
    }
}

contract AdversarialReputationTest is Test {
    IdentityRegistry identity;
    ReputationRegistry reputation;

    uint256 agentPk = 0xA11CE;
    address agentOwner;
    address client = address(0xC0FFEE);

    function setUp() public {
        identity = new IdentityRegistry();
        reputation = new ReputationRegistry(address(identity));
        agentOwner = vm.addr(agentPk);
    }

    function _register(uint256 pk) internal returns (uint256 id) {
        vm.prank(vm.addr(pk));
        id = identity.register("ipfs://card");
    }

    function _sign(uint256 pk, uint256 agentId, address who, uint64 expiry, bytes32 nonce)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash =
            keccak256(abi.encode(reputation.FEEDBACK_AUTH_TYPEHASH(), agentId, who, expiry, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", reputation.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// ATTACK: the agent owns its own identity AND holds the signing key, so it can
    /// authorize ITSELF as the client and farm a perfect 100 score indefinitely,
    /// defeating the whole "feedback must be authorized so reviews are real" premise.
    /// After the fix this must revert.
    function test_Attack_SelfFeedbackInflationBlocked() public {
        uint256 a = _register(agentPk); // owner == agentOwner
        uint64 expiry = uint64(block.timestamp + 3600);
        bytes32 nonce = keccak256("self-1");
        // owner signs an auth naming ITSELF as the client
        bytes memory sig = _sign(agentPk, a, agentOwner, expiry, nonce);

        vm.prank(agentOwner);
        vm.expectRevert("self feedback");
        reputation.giveFeedback(a, 100, 0, "", expiry, nonce, sig);
    }

    /// A legitimate third-party client can still rate (regression guard for the fix).
    function test_LegitClientStillWorks() public {
        uint256 a = _register(agentPk);
        uint64 expiry = uint64(block.timestamp + 3600);
        bytes32 nonce = keccak256("ok-1");
        bytes memory sig = _sign(agentPk, a, client, expiry, nonce);
        vm.prank(client);
        reputation.giveFeedback(a, 77, 0, "", expiry, nonce, sig);
        (uint64 n,, uint256 avg) = reputation.getSummary(a);
        assertEq(n, 1);
        assertEq(avg, 77);
    }

    /// ATTACK: forge an auth with a key that is NOT the agent owner.
    function test_Attack_ForgedSignerRejected() public {
        uint256 a = _register(agentPk);
        uint64 expiry = uint64(block.timestamp + 3600);
        bytes32 nonce = keccak256("forge");
        bytes memory sig = _sign(0xBADBAD, a, client, expiry, nonce); // wrong key
        vm.prank(client);
        vm.expectRevert("auth not signed by agent owner");
        reputation.giveFeedback(a, 90, 0, "", expiry, nonce, sig);
    }

    /// ATTACK: an auth signed by the OLD owner becomes useless after the identity
    /// is transferred (ownerOf changes), so a sold/handed-off agent can't be rated
    /// with stale authorizations.
    function test_Attack_AuthDeadAfterIdentityTransfer() public {
        uint256 a = _register(agentPk);
        uint64 expiry = uint64(block.timestamp + 3600);
        bytes32 nonce = keccak256("transfer");
        bytes memory sig = _sign(agentPk, a, client, expiry, nonce); // signed by old owner

        address newOwner = address(0xBEEF);
        vm.prank(agentOwner);
        identity.transferFrom(agentOwner, newOwner, a);

        vm.prank(client);
        vm.expectRevert("auth not signed by agent owner");
        reputation.giveFeedback(a, 90, 0, "", expiry, nonce, sig);
    }

    /// ATTACK: v outside {27,28} (here it survives the <27 bump but lands on 29).
    function test_Attack_BadVRejected() public {
        uint256 a = _register(agentPk);
        uint64 expiry = uint64(block.timestamp + 3600);
        bytes32 nonce = keccak256("badv");
        bytes32 structHash = keccak256(abi.encode(reputation.FEEDBACK_AUTH_TYPEHASH(), a, client, expiry, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", reputation.DOMAIN_SEPARATOR(), structHash));
        (, bytes32 r, bytes32 s) = vm.sign(agentPk, digest);
        bytes memory badSig = abi.encodePacked(r, s, uint8(29));
        vm.prank(client);
        vm.expectRevert("bad sig v");
        reputation.giveFeedback(a, 90, 0, "", expiry, nonce, badSig);
    }

    /// ATTACK: truncated 64-byte signature.
    function test_Attack_ShortSignatureRejected() public {
        uint256 a = _register(agentPk);
        uint64 expiry = uint64(block.timestamp + 3600);
        bytes32 nonce = keccak256("short");
        bytes memory sig = _sign(agentPk, a, client, expiry, nonce);
        bytes memory truncated = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            truncated[i] = sig[i];
        }
        vm.prank(client);
        vm.expectRevert("bad sig length");
        reputation.giveFeedback(a, 90, 0, "", expiry, nonce, truncated);
    }

    /// ATTACK: all-zero signature must not recover address(0) into a valid signer.
    function test_Attack_ZeroSignatureRejected() public {
        uint256 a = _register(agentPk);
        uint64 expiry = uint64(block.timestamp + 3600);
        bytes32 nonce = keccak256("zero");
        bytes memory sig = new bytes(65); // all zero; v becomes 27 after the <27 bump
        vm.prank(client);
        vm.expectRevert(); // "invalid signature" (ecrecover -> 0) or "bad sig s"
        reputation.giveFeedback(a, 90, 0, "", expiry, nonce, sig);
    }

    /// Edge: score 0 is a legitimate (worst) rating, not a reject.
    function test_ScoreZeroIsValid() public {
        uint256 a = _register(agentPk);
        uint64 expiry = uint64(block.timestamp + 3600);
        bytes32 nonce = keccak256("zeroscore");
        bytes memory sig = _sign(agentPk, a, client, expiry, nonce);
        vm.prank(client);
        reputation.giveFeedback(a, 0, 0, "", expiry, nonce, sig);
        (uint64 n,, uint256 avg) = reputation.getSummary(a);
        assertEq(n, 1);
        assertEq(avg, 0);
    }
}

contract AdversarialEscrowTest is Test {
    IdentityRegistry identity;
    JobEscrow escrow;

    address client = address(0xC11E47);
    address provider = address(0x9803);
    uint256 constant AMT = 1_000_000;

    function setUp() public {
        identity = new IdentityRegistry();
        escrow = new JobEscrow(address(identity));
    }

    function _fund(MockUSDC2 t, uint64 deadline, uint64 reviewWindow) internal returns (uint256 jobId) {
        t.mint(client, 100 * AMT);
        vm.startPrank(client);
        t.approve(address(escrow), AMT);
        jobId = escrow.createJob(provider, 0, IERC20(address(t)), AMT, deadline, reviewWindow);
        vm.stopPrank();
    }

    /// ATTACK: re-enter refund() while it pays the client back. Mutex must block it
    /// so the client cannot pull the escrow twice.
    function test_Attack_ReentrancyOnRefund() public {
        MultiReentrantToken t = new MultiReentrantToken();
        t.mint(client, 100 * AMT);
        vm.startPrank(client);
        t.approve(address(escrow), AMT);
        uint256 jobId =
            escrow.createJob(provider, 0, IERC20(address(t)), AMT, uint64(block.timestamp + 1 days), 1 hours);
        vm.stopPrank();

        vm.warp(block.timestamp + 1 days + 1);
        t.arm(escrow, jobId, MultiReentrantToken.Target.Refund);
        vm.prank(client);
        escrow.refund(jobId);

        assertTrue(t.attempted());
        assertTrue(t.reverted());
        assertEq(t.balanceOf(client), 100 * AMT); // exactly one refund, not two
        assertEq(t.balanceOf(address(escrow)), 0);
    }

    /// ATTACK: re-enter claim() during provider self-claim payout.
    function test_Attack_ReentrancyOnClaim() public {
        MultiReentrantToken t = new MultiReentrantToken();
        t.mint(client, 100 * AMT);
        vm.startPrank(client);
        t.approve(address(escrow), AMT);
        uint256 jobId =
            escrow.createJob(provider, 0, IERC20(address(t)), AMT, uint64(block.timestamp + 1 days), 1 hours);
        vm.stopPrank();
        vm.prank(provider);
        escrow.submit(jobId, keccak256("w"));
        vm.warp(block.timestamp + 1 hours + 1);

        t.arm(escrow, jobId, MultiReentrantToken.Target.Claim);
        vm.prank(provider);
        escrow.claim(jobId);

        assertTrue(t.attempted());
        assertTrue(t.reverted());
        assertEq(t.balanceOf(provider), AMT); // paid once
    }

    /// ATTACK: cross-function reentrancy — during release() of job A, the token tries
    /// to refund a different funded job B. Global mutex must reject it.
    function test_Attack_CrossFunctionReleaseToRefund() public {
        MultiReentrantToken t = new MultiReentrantToken();
        t.mint(client, 100 * AMT);
        vm.startPrank(client);
        t.approve(address(escrow), 2 * AMT);
        uint256 jobA =
            escrow.createJob(provider, 0, IERC20(address(t)), AMT, uint64(block.timestamp + 1 days), 1 hours);
        uint256 jobB =
            escrow.createJob(provider, 0, IERC20(address(t)), AMT, uint64(block.timestamp + 1 days), 1 hours);
        vm.stopPrank();
        vm.prank(provider);
        escrow.submit(jobA, keccak256("a"));

        // B is still Funded; make it refundable in time, then re-enter refund(B) from release(A)
        vm.warp(block.timestamp + 1 days + 1);
        // jobA submitted before the warp, so it is still Submitted (submit happened earlier)
        t.arm(escrow, jobB, MultiReentrantToken.Target.Refund);
        vm.prank(client);
        escrow.release(jobA);

        assertTrue(t.reverted()); // refund(B) re-entry blocked
        assertEq(t.balanceOf(provider), AMT); // only A paid
        assertEq(t.balanceOf(address(escrow)), AMT); // B still escrowed
        assertEq(uint8(escrow.statusOf(jobB)), uint8(JobEscrow.Status.Funded));
    }

    /// ATTACK: claim exactly at the review-window boundary must fail (strict >).
    function test_Attack_ClaimAtExactBoundaryReverts() public {
        MockUSDC2 t = new MockUSDC2();
        uint256 jobId = _fund(t, uint64(block.timestamp + 1 days), 1 hours);
        vm.prank(provider);
        escrow.submit(jobId, keccak256("w"));
        // jump to exactly submittedAt + reviewWindow
        vm.warp(block.timestamp + 1 hours);
        vm.prank(provider);
        vm.expectRevert("review window open");
        escrow.claim(jobId);
        // one second later it succeeds
        vm.warp(block.timestamp + 1);
        vm.prank(provider);
        escrow.claim(jobId);
        assertEq(t.balanceOf(provider), AMT);
    }

    /// ATTACK: provider tries to claim a Funded (never-submitted) job to skip delivery.
    function test_Attack_CannotClaimWithoutSubmit() public {
        MockUSDC2 t = new MockUSDC2();
        uint256 jobId = _fund(t, uint64(block.timestamp + 1 days), 1 hours);
        vm.warp(block.timestamp + 365 days);
        vm.prank(provider);
        vm.expectRevert("not submitted");
        escrow.claim(jobId);
    }

    /// ATTACK: after a refund, every other terminal action on that job is dead.
    function test_Attack_NoActionAfterRefund() public {
        MockUSDC2 t = new MockUSDC2();
        uint256 jobId = _fund(t, uint64(block.timestamp + 1 days), 1 hours);
        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(client);
        escrow.refund(jobId);

        vm.prank(provider);
        vm.expectRevert("not funded");
        escrow.submit(jobId, keccak256("late"));
        vm.prank(client);
        vm.expectRevert("not submitted");
        escrow.release(jobId);
        vm.prank(client);
        vm.expectRevert("not refundable");
        escrow.refund(jobId);
    }

    /// ATTACK: client tries to refund a delivered (Submitted) job to dodge payment.
    function test_Attack_CannotRefundAfterSubmit() public {
        MockUSDC2 t = new MockUSDC2();
        uint256 jobId = _fund(t, uint64(block.timestamp + 1 days), 1 hours);
        vm.prank(provider);
        escrow.submit(jobId, keccak256("w"));
        vm.warp(block.timestamp + 365 days);
        vm.prank(client);
        vm.expectRevert("not refundable");
        escrow.refund(jobId);
    }
}
