// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/JobEscrow.sol";
import "../src/IdentityRegistry.sol";

// --- standard mock ERC-20 ---
contract MockUSDC {
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

    function transfer(address to, uint256 amt) public virtual returns (bool) {
        require(balanceOf[msg.sender] >= amt, "balance");
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt;
        return true;
    }

    function transferFrom(address from, address to, uint256 amt) public virtual returns (bool) {
        require(balanceOf[from] >= amt, "balance");
        uint256 a = allowance[from][msg.sender];
        require(a >= amt, "allowance");
        if (a != type(uint256).max) allowance[from][msg.sender] = a - amt;
        balanceOf[from] -= amt;
        balanceOf[to] += amt;
        return true;
    }
}

// --- fee-on-transfer token: skims 10% on every transfer ---
contract FeeToken is MockUSDC {
    function transferFrom(address from, address to, uint256 amt) public override returns (bool) {
        require(balanceOf[from] >= amt, "balance");
        uint256 a = allowance[from][msg.sender];
        require(a >= amt, "allowance");
        if (a != type(uint256).max) allowance[from][msg.sender] = a - amt;
        uint256 fee = amt / 10;
        balanceOf[from] -= amt;
        balanceOf[to] += (amt - fee);
        // fee burned
        return true;
    }
}

// --- non-bool-returning token (like real USDT): returns no data ---
contract NoReturnToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amt) external {
        balanceOf[to] += amt;
    }

    function approve(address spender, uint256 amt) external {
        allowance[msg.sender][spender] = amt;
    }

    function transfer(address to, uint256 amt) external {
        require(balanceOf[msg.sender] >= amt, "balance");
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt;
        // no return
    }

    function transferFrom(address from, address to, uint256 amt) external {
        require(balanceOf[from] >= amt, "balance");
        require(allowance[from][msg.sender] >= amt, "allowance");
        allowance[from][msg.sender] -= amt;
        balanceOf[from] -= amt;
        balanceOf[to] += amt;
        // no return
    }
}

// --- reentrancy attack token: on transfer, re-enters the escrow ---
contract ReentrantToken is MockUSDC {
    JobEscrow public escrow;
    uint256 public reentryTarget;
    bool internal armed;
    bool public reentryAttempted;
    bool public reentryReverted;

    function arm(JobEscrow _e, uint256 _target) external {
        escrow = _e;
        reentryTarget = _target;
        armed = true;
    }

    function transfer(address to, uint256 amt) public override returns (bool) {
        if (armed) {
            armed = false; // re-enter once
            reentryAttempted = true;
            // try to re-enter the escrow during payout; the guard must make this fail
            try escrow.release(reentryTarget) {
                reentryReverted = false; // attack succeeded -> bad
            } catch {
                reentryReverted = true; // attack blocked -> good
            }
        }
        return super.transfer(to, amt);
    }
}

contract JobEscrowTest is Test {
    IdentityRegistry identity;
    JobEscrow escrow;
    MockUSDC usdc;

    address client = address(0xC11E47);
    address provider = address(0x9803);
    uint256 constant AMT = 1_000_000; // 1 USDC (6 decimals)

    function setUp() public {
        identity = new IdentityRegistry();
        escrow = new JobEscrow(address(identity));
        usdc = new MockUSDC();
        usdc.mint(client, 100 * AMT);
    }

    function _fund(uint64 deadline, uint64 reviewWindow) internal returns (uint256 jobId) {
        vm.startPrank(client);
        usdc.approve(address(escrow), AMT);
        jobId = escrow.createJob(provider, 0, IERC20(address(usdc)), AMT, deadline, reviewWindow);
        vm.stopPrank();
    }

    // ---------- happy paths ----------

    function test_FundSubmitRelease() public {
        uint256 jobId = _fund(uint64(block.timestamp + 1 days), 1 hours);
        assertEq(usdc.balanceOf(address(escrow)), AMT);

        vm.prank(provider);
        escrow.submit(jobId, keccak256("work"));

        vm.prank(client);
        escrow.release(jobId);

        assertEq(usdc.balanceOf(provider), AMT);
        assertEq(usdc.balanceOf(address(escrow)), 0);
        assertEq(uint8(escrow.statusOf(jobId)), uint8(JobEscrow.Status.Completed));
    }

    function test_ProviderClaimAfterReviewWindow() public {
        uint256 jobId = _fund(uint64(block.timestamp + 1 days), 1 hours);
        vm.prank(provider);
        escrow.submit(jobId, keccak256("work"));

        vm.warp(block.timestamp + 1 hours + 1);
        vm.prank(provider);
        escrow.claim(jobId);

        assertEq(usdc.balanceOf(provider), AMT);
    }

    function test_RefundAfterDeadlineNoDelivery() public {
        uint256 jobId = _fund(uint64(block.timestamp + 1 days), 1 hours);
        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(client);
        escrow.refund(jobId);
        assertEq(usdc.balanceOf(client), 100 * AMT);
        assertEq(uint8(escrow.statusOf(jobId)), uint8(JobEscrow.Status.Refunded));
    }

    // ---------- access control ----------

    function test_OnlyProviderCanSubmit() public {
        uint256 jobId = _fund(uint64(block.timestamp + 1 days), 1 hours);
        vm.prank(client);
        vm.expectRevert("not provider");
        escrow.submit(jobId, keccak256("x"));
    }

    function test_OnlyClientCanRelease() public {
        uint256 jobId = _fund(uint64(block.timestamp + 1 days), 1 hours);
        vm.prank(provider);
        escrow.submit(jobId, keccak256("work"));
        vm.prank(provider);
        vm.expectRevert("not client");
        escrow.release(jobId);
    }

    function test_OnlyProviderCanClaim() public {
        uint256 jobId = _fund(uint64(block.timestamp + 1 days), 1 hours);
        vm.prank(provider);
        escrow.submit(jobId, keccak256("work"));
        vm.warp(block.timestamp + 1 hours + 1);
        vm.prank(client);
        vm.expectRevert("not provider");
        escrow.claim(jobId);
    }

    function test_OnlyClientCanRefund() public {
        uint256 jobId = _fund(uint64(block.timestamp + 1 days), 1 hours);
        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(provider);
        vm.expectRevert("not client");
        escrow.refund(jobId);
    }

    // ---------- state machine ----------

    function test_CannotReleaseBeforeSubmit() public {
        uint256 jobId = _fund(uint64(block.timestamp + 1 days), 1 hours);
        vm.prank(client);
        vm.expectRevert("not submitted");
        escrow.release(jobId);
    }

    function test_CannotSubmitAfterDeadline() public {
        uint256 jobId = _fund(uint64(block.timestamp + 1 days), 1 hours);
        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(provider);
        vm.expectRevert("submit deadline passed");
        escrow.submit(jobId, keccak256("late"));
    }

    function test_CannotClaimBeforeReviewWindow() public {
        uint256 jobId = _fund(uint64(block.timestamp + 1 days), 1 hours);
        vm.prank(provider);
        escrow.submit(jobId, keccak256("work"));
        vm.prank(provider);
        vm.expectRevert("review window open");
        escrow.claim(jobId);
    }

    function test_CannotRefundBeforeDeadline() public {
        uint256 jobId = _fund(uint64(block.timestamp + 1 days), 1 hours);
        vm.prank(client);
        vm.expectRevert("deadline not passed");
        escrow.refund(jobId);
    }

    function test_CannotDoubleRelease() public {
        uint256 jobId = _fund(uint64(block.timestamp + 1 days), 1 hours);
        vm.prank(provider);
        escrow.submit(jobId, keccak256("work"));
        vm.prank(client);
        escrow.release(jobId);
        vm.prank(client);
        vm.expectRevert("not submitted");
        escrow.release(jobId);
    }

    function test_CannotRefundAfterRelease() public {
        uint256 jobId = _fund(uint64(block.timestamp + 1 days), 1 hours);
        vm.prank(provider);
        escrow.submit(jobId, keccak256("work"));
        vm.prank(client);
        escrow.release(jobId);
        vm.warp(block.timestamp + 2 days);
        vm.prank(client);
        vm.expectRevert("not refundable");
        escrow.refund(jobId);
    }

    // ---------- createJob guards ----------

    function test_RejectSelfJob() public {
        vm.startPrank(client);
        usdc.approve(address(escrow), AMT);
        vm.expectRevert("self job");
        escrow.createJob(client, 0, IERC20(address(usdc)), AMT, uint64(block.timestamp + 1 days), 1 hours);
        vm.stopPrank();
    }

    function test_RejectZeroProvider() public {
        vm.startPrank(client);
        usdc.approve(address(escrow), AMT);
        vm.expectRevert("provider zero");
        escrow.createJob(address(0), 0, IERC20(address(usdc)), AMT, uint64(block.timestamp + 1 days), 1 hours);
        vm.stopPrank();
    }

    function test_RejectZeroAmount() public {
        vm.startPrank(client);
        usdc.approve(address(escrow), AMT);
        vm.expectRevert("amount zero");
        escrow.createJob(provider, 0, IERC20(address(usdc)), 0, uint64(block.timestamp + 1 days), 1 hours);
        vm.stopPrank();
    }

    function test_RejectPastDeadline() public {
        vm.startPrank(client);
        usdc.approve(address(escrow), AMT);
        vm.expectRevert("deadline in past");
        escrow.createJob(provider, 0, IERC20(address(usdc)), AMT, uint64(block.timestamp), 1 hours);
        vm.stopPrank();
    }

    function test_AgentProviderMismatchReverts() public {
        // register agent owned by `provider`
        vm.prank(provider);
        uint256 agentId = identity.register("ipfs://card");
        // try to create a job naming a DIFFERENT provider with that agentId
        vm.startPrank(client);
        usdc.approve(address(escrow), AMT);
        vm.expectRevert("agent/provider mismatch");
        escrow.createJob(address(0xBEEF), agentId, IERC20(address(usdc)), AMT, uint64(block.timestamp + 1 days), 1 hours);
        vm.stopPrank();
    }

    function test_AgentLinkedJobOK() public {
        vm.prank(provider);
        uint256 agentId = identity.register("ipfs://card");
        vm.startPrank(client);
        usdc.approve(address(escrow), AMT);
        uint256 jobId =
            escrow.createJob(provider, agentId, IERC20(address(usdc)), AMT, uint64(block.timestamp + 1 days), 1 hours);
        vm.stopPrank();
        (,, uint256 linkedAgent,,,,,,,) = escrow.jobs(jobId);
        assertEq(linkedAgent, agentId);
    }

    // ---------- token edge cases ----------

    function test_FeeOnTransferEscrowsActualReceived() public {
        FeeToken fee = new FeeToken();
        fee.mint(client, 100 * AMT);
        vm.startPrank(client);
        fee.approve(address(escrow), AMT);
        uint256 jobId = escrow.createJob(provider, 0, IERC20(address(fee)), AMT, uint64(block.timestamp + 1 days), 1 hours);
        vm.stopPrank();
        // escrow received only 90%
        (,,,, uint256 amount,,,,,) = escrow.jobs(jobId);
        assertEq(amount, AMT - AMT / 10);
        assertEq(fee.balanceOf(address(escrow)), AMT - AMT / 10);

        // payout uses the real escrowed amount, so the escrow never goes negative
        vm.prank(provider);
        escrow.submit(jobId, keccak256("work"));
        vm.prank(client);
        escrow.release(jobId);
        assertEq(fee.balanceOf(address(escrow)), 0);
    }

    function test_NoReturnTokenWorks() public {
        NoReturnToken nrt = new NoReturnToken();
        nrt.mint(client, 100 * AMT);
        vm.startPrank(client);
        nrt.approve(address(escrow), AMT);
        uint256 jobId = escrow.createJob(provider, 0, IERC20(address(nrt)), AMT, uint64(block.timestamp + 1 days), 1 hours);
        vm.stopPrank();
        vm.prank(provider);
        escrow.submit(jobId, keccak256("work"));
        vm.prank(client);
        escrow.release(jobId);
        assertEq(nrt.balanceOf(provider), AMT);
    }

    // ---------- fuzz ----------

    function testFuzz_ReleasePaysExactly(uint256 amount) public {
        amount = bound(amount, 1, 50 * AMT);
        vm.startPrank(client);
        usdc.approve(address(escrow), amount);
        uint256 jobId =
            escrow.createJob(provider, 0, IERC20(address(usdc)), amount, uint64(block.timestamp + 1 days), 1 hours);
        vm.stopPrank();
        vm.prank(provider);
        escrow.submit(jobId, keccak256("w"));
        vm.prank(client);
        escrow.release(jobId);
        assertEq(usdc.balanceOf(provider), amount);
        assertEq(usdc.balanceOf(address(escrow)), 0);
    }

    function testFuzz_NonClientCannotRelease(address rando) public {
        vm.assume(rando != client);
        uint256 jobId = _fund(uint64(block.timestamp + 1 days), 1 hours);
        vm.prank(provider);
        escrow.submit(jobId, keccak256("w"));
        vm.prank(rando);
        vm.expectRevert("not client");
        escrow.release(jobId);
    }

    function testFuzz_NonProviderCannotClaim(address rando) public {
        vm.assume(rando != provider);
        uint256 jobId = _fund(uint64(block.timestamp + 1 days), 1 hours);
        vm.prank(provider);
        escrow.submit(jobId, keccak256("w"));
        vm.warp(block.timestamp + 1 hours + 1);
        vm.prank(rando);
        vm.expectRevert("not provider");
        escrow.claim(jobId);
    }

    // ---------- reentrancy ----------

    function test_ReentrancySameJobBlockedNoDoublePay() public {
        ReentrantToken rt = new ReentrantToken();
        rt.mint(client, 100 * AMT);
        vm.startPrank(client);
        rt.approve(address(escrow), AMT);
        uint256 jobId = escrow.createJob(provider, 0, IERC20(address(rt)), AMT, uint64(block.timestamp + 1 days), 1 hours);
        vm.stopPrank();
        vm.prank(provider);
        escrow.submit(jobId, keccak256("work"));

        // token re-enters release(jobId) during payout; the guard must block it
        rt.arm(escrow, jobId);
        vm.prank(client);
        escrow.release(jobId);

        // attack happened but was rejected, and the provider got paid exactly once
        assertTrue(rt.reentryAttempted());
        assertTrue(rt.reentryReverted());
        assertEq(rt.balanceOf(provider), AMT); // not 2*AMT
        assertEq(uint8(escrow.statusOf(jobId)), uint8(JobEscrow.Status.Completed));
    }

    function test_ReentrancyOtherJobNotDrained() public {
        ReentrantToken rt = new ReentrantToken();
        rt.mint(client, 100 * AMT);

        // job A and job B both funded with the malicious token
        vm.startPrank(client);
        rt.approve(address(escrow), 2 * AMT);
        uint256 jobA = escrow.createJob(provider, 0, IERC20(address(rt)), AMT, uint64(block.timestamp + 1 days), 1 hours);
        uint256 jobB = escrow.createJob(provider, 0, IERC20(address(rt)), AMT, uint64(block.timestamp + 1 days), 1 hours);
        vm.stopPrank();

        vm.prank(provider);
        escrow.submit(jobA, keccak256("a"));
        vm.prank(provider);
        escrow.submit(jobB, keccak256("b"));

        // releasing A re-enters to drain B; the mutex must block the re-entry
        rt.arm(escrow, jobB);
        vm.prank(client);
        escrow.release(jobA);

        // A paid once, B untouched and still escrowed
        assertTrue(rt.reentryReverted());
        assertEq(rt.balanceOf(provider), AMT); // only A
        assertEq(uint8(escrow.statusOf(jobB)), uint8(JobEscrow.Status.Submitted));
        assertEq(rt.balanceOf(address(escrow)), AMT); // B's funds still locked
    }
}
