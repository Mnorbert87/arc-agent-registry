// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IIdentity {
    function ownerOf(uint256 agentId) external view returns (address);
    function exists(uint256 agentId) external view returns (bool);
}

/// @title JobEscrow
/// @notice Payment-for-work escrow for the Arc agent economy (ERC-8183 aligned, simplified).
///         A client funds a job in USDC; the provider agent delivers; the client releases
///         payment. If the provider never delivers by the deadline the client reclaims the
///         funds; if the client goes silent after a delivery, the provider can claim once a
///         review window passes. The contract is token-agnostic but intended for Arc USDC
///         (`0x3600...`). It holds funds for exactly one outcome per job and never more than
///         what was actually escrowed.
///
/// @dev    Security posture:
///         - Checks-Effects-Interactions on every payout (state moved to a terminal status
///           BEFORE any token transfer) plus a global non-reentrancy mutex.
///         - Custody is measured by balance delta on funding, so a fee-on-transfer token can
///           never let a job claim to hold more than it received.
///         - Low-level transfer helpers tolerate non-standard ERC-20s that return no value.
///         - No admin, no upgrade, no pause: nobody (not even the deployer) can move a job's
///           funds except along the job's own state machine.
contract JobEscrow {
    IIdentity public immutable identity;

    enum Status {
        None,
        Funded, // client has escrowed funds, awaiting delivery
        Submitted, // provider delivered, awaiting client release or review-window claim
        Completed, // paid out to provider (terminal)
        Refunded // returned to client (terminal)
    }

    struct Job {
        address client;
        address provider;
        uint256 providerAgentId; // ERC-8004 identity of the provider (0 = unlinked)
        IERC20 token;
        uint256 amount; // actual escrowed amount (post balance-delta)
        uint64 submitDeadline; // provider must submit by this time
        uint64 reviewWindow; // seconds after submit before provider may self-claim
        uint64 submittedAt; // timestamp of submit (0 until submitted)
        bytes32 deliverable; // hash/URI digest of the delivered work
        Status status;
    }

    uint256 public nextJobId = 1;
    mapping(uint256 => Job) public jobs;

    // --- reentrancy mutex ---
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _lock = _NOT_ENTERED;

    modifier nonReentrant() {
        require(_lock == _NOT_ENTERED, "reentrant");
        _lock = _ENTERED;
        _;
        _lock = _NOT_ENTERED;
    }

    event JobCreated(
        uint256 indexed jobId,
        address indexed client,
        address indexed provider,
        uint256 providerAgentId,
        address token,
        uint256 amount,
        uint64 submitDeadline,
        uint64 reviewWindow
    );
    event JobSubmitted(uint256 indexed jobId, bytes32 deliverable);
    event JobReleased(uint256 indexed jobId, address indexed provider, uint256 amount);
    event JobRefunded(uint256 indexed jobId, address indexed client, uint256 amount);

    constructor(address identityRegistry) {
        identity = IIdentity(identityRegistry);
    }

    /// @notice Create and fund a job. The caller (client) must have approved `amount` of
    ///         `token` to this contract. The escrowed amount is the actual balance delta,
    ///         so fee-on-transfer tokens are accounted correctly.
    /// @param provider        The address paid on completion.
    /// @param providerAgentId Optional ERC-8004 agentId of the provider (0 to skip the link).
    /// @param token           ERC-20 used for payment (Arc USDC in production).
    /// @param amount          Amount to pull from the client into escrow.
    /// @param submitDeadline  Unix time by which the provider must submit.
    /// @param reviewWindow    Seconds after submit before the provider may self-claim.
    function createJob(
        address provider,
        uint256 providerAgentId,
        IERC20 token,
        uint256 amount,
        uint64 submitDeadline,
        uint64 reviewWindow
    ) external nonReentrant returns (uint256 jobId) {
        require(provider != address(0), "provider zero");
        require(provider != msg.sender, "self job");
        require(amount > 0, "amount zero");
        require(submitDeadline > block.timestamp, "deadline in past");
        if (providerAgentId != 0) {
            require(identity.exists(providerAgentId), "no such agent");
            require(identity.ownerOf(providerAgentId) == provider, "agent/provider mismatch");
        }

        uint256 balBefore = token.balanceOf(address(this));
        _safeTransferFrom(token, msg.sender, address(this), amount);
        uint256 received = token.balanceOf(address(this)) - balBefore;
        require(received > 0, "no funds received");

        jobId = nextJobId++;
        jobs[jobId] = Job({
            client: msg.sender,
            provider: provider,
            providerAgentId: providerAgentId,
            token: token,
            amount: received,
            submitDeadline: submitDeadline,
            reviewWindow: reviewWindow,
            submittedAt: 0,
            deliverable: bytes32(0),
            status: Status.Funded
        });

        emit JobCreated(
            jobId, msg.sender, provider, providerAgentId, address(token), received, submitDeadline, reviewWindow
        );
    }

    /// @notice Provider delivers the work. Records a digest and starts the review window.
    function submit(uint256 jobId, bytes32 deliverable) external {
        Job storage job = jobs[jobId];
        require(job.status == Status.Funded, "not funded");
        require(msg.sender == job.provider, "not provider");
        require(block.timestamp <= job.submitDeadline, "submit deadline passed");
        require(deliverable != bytes32(0), "empty deliverable");

        job.submittedAt = uint64(block.timestamp);
        job.deliverable = deliverable;
        job.status = Status.Submitted;
        emit JobSubmitted(jobId, deliverable);
    }

    /// @notice Client accepts the delivery and releases payment to the provider.
    function release(uint256 jobId) external nonReentrant {
        Job storage job = jobs[jobId];
        require(job.status == Status.Submitted, "not submitted");
        require(msg.sender == job.client, "not client");

        job.status = Status.Completed; // effect before interaction
        _safeTransfer(job.token, job.provider, job.amount);
        emit JobReleased(jobId, job.provider, job.amount);
    }

    /// @notice Provider self-claims payment if the client has not released within the review
    ///         window after submission. Prevents a silent client from locking funds forever.
    function claim(uint256 jobId) external nonReentrant {
        Job storage job = jobs[jobId];
        require(job.status == Status.Submitted, "not submitted");
        require(msg.sender == job.provider, "not provider");
        require(block.timestamp > uint256(job.submittedAt) + uint256(job.reviewWindow), "review window open");

        job.status = Status.Completed; // effect before interaction
        _safeTransfer(job.token, job.provider, job.amount);
        emit JobReleased(jobId, job.provider, job.amount);
    }

    /// @notice Client reclaims funds if the provider never delivered by the deadline.
    function refund(uint256 jobId) external nonReentrant {
        Job storage job = jobs[jobId];
        require(job.status == Status.Funded, "not refundable");
        require(msg.sender == job.client, "not client");
        require(block.timestamp > job.submitDeadline, "deadline not passed");

        job.status = Status.Refunded; // effect before interaction
        _safeTransfer(job.token, job.client, job.amount);
        emit JobRefunded(jobId, job.client, job.amount);
    }

    /// @notice Convenience read of a job's lifecycle status.
    function statusOf(uint256 jobId) external view returns (Status) {
        return jobs[jobId].status;
    }

    // --- safe ERC-20 helpers (tolerate non-bool-returning tokens) ---

    function _safeTransfer(IERC20 token, address to, uint256 amount) private {
        (bool ok, bytes memory data) = address(token).call(abi.encodeWithSelector(token.transfer.selector, to, amount));
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "transfer failed");
    }

    function _safeTransferFrom(IERC20 token, address from, address to, uint256 amount) private {
        (bool ok, bytes memory data) =
            address(token).call(abi.encodeWithSelector(token.transferFrom.selector, from, to, amount));
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "transferFrom failed");
    }
}
