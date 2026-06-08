// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/JobEscrow.sol";

// Minimal mint-on-demand ERC-20 for invariant fuzzing.
contract FuzzUSDC {
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
        require(balanceOf[msg.sender] >= amt, "bal");
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt;
        return true;
    }

    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        require(balanceOf[from] >= amt, "bal");
        require(allowance[from][msg.sender] >= amt, "allow");
        allowance[from][msg.sender] -= amt;
        balanceOf[from] -= amt;
        balanceOf[to] += amt;
        return true;
    }
}

/// Drives random valid actions against the escrow. Several clients and providers so the
/// fuzzer exercises access control and the full state machine.
contract Handler is Test {
    JobEscrow public escrow;
    FuzzUSDC public usdc;
    uint256[] public jobIds;

    address[] internal clients = [address(0xC1), address(0xC2), address(0xC3)];
    address[] internal providers = [address(0xD1), address(0xD2)];

    constructor(JobEscrow _escrow, FuzzUSDC _usdc) {
        escrow = _escrow;
        usdc = _usdc;
    }

    function createJob(uint256 cSeed, uint256 pSeed, uint256 amount, uint64 dl, uint64 rw) external {
        address c = clients[cSeed % clients.length];
        address p = providers[pSeed % providers.length];
        if (c == p) return;
        amount = bound(amount, 1, 1e12);
        dl = uint64(bound(dl, block.timestamp + 1, block.timestamp + 365 days));
        rw = uint64(bound(rw, 0, 30 days));

        usdc.mint(c, amount);
        vm.startPrank(c);
        usdc.approve(address(escrow), amount);
        uint256 id = escrow.createJob(p, 0, IERC20(address(usdc)), amount, dl, rw);
        vm.stopPrank();
        jobIds.push(id);
    }

    function submit(uint256 idx) external {
        if (jobIds.length == 0) return;
        uint256 id = jobIds[idx % jobIds.length];
        (, address p,,,, uint64 dl,,,, JobEscrow.Status st) = escrow.jobs(id);
        if (st != JobEscrow.Status.Funded || block.timestamp > dl) return;
        vm.prank(p);
        escrow.submit(id, keccak256(abi.encode(id)));
    }

    function release(uint256 idx) external {
        if (jobIds.length == 0) return;
        uint256 id = jobIds[idx % jobIds.length];
        (address c,,,,,,,,, JobEscrow.Status st) = escrow.jobs(id);
        if (st != JobEscrow.Status.Submitted) return;
        vm.prank(c);
        escrow.release(id);
    }

    function claim(uint256 idx, uint64 jump) external {
        if (jobIds.length == 0) return;
        uint256 id = jobIds[idx % jobIds.length];
        (, address p,,,,, uint64 rw, uint64 subAt,, JobEscrow.Status st) = escrow.jobs(id);
        if (st != JobEscrow.Status.Submitted) return;
        vm.warp(uint256(subAt) + uint256(rw) + bound(jump, 1, 10 days));
        vm.prank(p);
        escrow.claim(id);
    }

    function refund(uint256 idx, uint64 jump) external {
        if (jobIds.length == 0) return;
        uint256 id = jobIds[idx % jobIds.length];
        (address c,,,,, uint64 dl,,,, JobEscrow.Status st) = escrow.jobs(id);
        if (st != JobEscrow.Status.Funded) return;
        vm.warp(uint256(dl) + bound(jump, 1, 10 days));
        vm.prank(c);
        escrow.refund(id);
    }

    function jobCount() external view returns (uint256) {
        return jobIds.length;
    }

    function jobAt(uint256 i) external view returns (uint256) {
        return jobIds[i];
    }
}

contract JobEscrowInvariantTest is Test {
    JobEscrow escrow;
    FuzzUSDC usdc;
    Handler handler;

    function setUp() public {
        escrow = new JobEscrow(address(0)); // identity unused (agentId 0 path)
        usdc = new FuzzUSDC();
        handler = new Handler(escrow, usdc);
        targetContract(address(handler));
    }

    /// The escrow's USDC balance must always equal the sum of funds still owed
    /// (jobs that are Funded or Submitted). Completed/Refunded jobs are paid out,
    /// so an over- or under-payment anywhere breaks this equality.
    function invariant_solvent() public view {
        uint256 n = handler.jobCount();
        uint256 owed;
        for (uint256 i = 0; i < n; i++) {
            uint256 id = handler.jobAt(i);
            (,,,, uint256 amount,,,,, JobEscrow.Status st) = escrow.jobs(id);
            if (st == JobEscrow.Status.Funded || st == JobEscrow.Status.Submitted) {
                owed += amount;
            }
        }
        assertEq(usdc.balanceOf(address(escrow)), owed);
    }
}
