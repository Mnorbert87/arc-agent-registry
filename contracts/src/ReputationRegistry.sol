// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IIdentityRegistry {
    function ownerOf(uint256 agentId) external view returns (address);
    function exists(uint256 agentId) external view returns (bool);
}

/// @title ReputationRegistry
/// @notice An ERC-8004 aligned reputation registry for Arc. Clients leave a score
///         (0-100) for an agent after an interaction. To stop spam and fake reviews,
///         feedback must be authorized by the agent itself: the agent owner signs an
///         EIP-712 FeedbackAuth granting one specific client the right to leave one
///         piece of feedback (single-use nonce). The contract verifies that signature
///         on-chain, so no prior authorization transaction is needed.
///
///         The registry keeps an O(1) running aggregate (count and total) per agent so
///         the average score is cheap to read. Pairs with x402: after a paid call, the
///         seller hands the buyer a FeedbackAuth, and the buyer rates the seller.
///
/// @dev    Faithful to the ERC-8004 Reputation model adapted for Arc testnet.
contract ReputationRegistry {
    IIdentityRegistry public immutable identity;

    // EIP-712
    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public constant FEEDBACK_AUTH_TYPEHASH =
        keccak256("FeedbackAuth(uint256 agentId,address client,uint64 expiry,bytes32 nonce)");

    // aggregates
    mapping(uint256 => uint64) public count; // number of feedbacks per agent
    mapping(uint256 => uint256) public total; // summed score per agent
    mapping(bytes32 => bool) public usedNonce; // per (agentId,nonce) replay guard

    struct Feedback {
        address client;
        uint8 score;
        bytes32 tag;
        uint64 timestamp;
        string fileURI;
    }

    mapping(uint256 => Feedback) public lastFeedback;

    event FeedbackGiven(
        uint256 indexed agentId, address indexed client, uint8 score, bytes32 indexed tag, string fileURI
    );

    constructor(address identityRegistry) {
        identity = IIdentityRegistry(identityRegistry);
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("ArcAgentReputation"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    /// @notice Leave feedback for an agent. Caller must be the `client` named in a
    ///         FeedbackAuth signed by the agent owner.
    /// @param agentId   The agent being rated.
    /// @param score     0-100.
    /// @param tag       A short bytes32 label (e.g. "memory-search"), or 0.
    /// @param fileURI   Optional URI to an off-chain detailed review, or "".
    /// @param expiry    FeedbackAuth expiry (unix seconds).
    /// @param nonce     Single-use nonce from the FeedbackAuth.
    /// @param signature The agent owner's EIP-712 signature over the FeedbackAuth.
    function giveFeedback(
        uint256 agentId,
        uint8 score,
        bytes32 tag,
        string calldata fileURI,
        uint64 expiry,
        bytes32 nonce,
        bytes calldata signature
    ) external {
        require(score <= 100, "score > 100");
        require(identity.exists(agentId), "no such agent");
        require(block.timestamp <= expiry, "auth expired");
        // The agent owner controls the signing key; without this guard it could name
        // itself as the client and farm an unbounded self-issued score, defeating the
        // "feedback must be authorized so reviews are real" premise. A counterparty
        // must be distinct from the agent owner.
        require(msg.sender != identity.ownerOf(agentId), "self feedback");

        bytes32 slot = keccak256(abi.encodePacked(agentId, nonce));
        require(!usedNonce[slot], "nonce used");

        bytes32 structHash = keccak256(abi.encode(FEEDBACK_AUTH_TYPEHASH, agentId, msg.sender, expiry, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address signer = _recover(digest, signature);
        require(signer == identity.ownerOf(agentId), "auth not signed by agent owner");

        usedNonce[slot] = true;
        unchecked {
            count[agentId] += 1;
            total[agentId] += score;
        }
        lastFeedback[agentId] =
            Feedback({client: msg.sender, score: score, tag: tag, timestamp: uint64(block.timestamp), fileURI: fileURI});

        emit FeedbackGiven(agentId, msg.sender, score, tag, fileURI);
    }

    /// @notice Aggregate reputation for an agent.
    /// @return n    Number of feedbacks.
    /// @return sum  Total score.
    /// @return average Average score (0-100), 0 if no feedback yet.
    function getSummary(uint256 agentId) external view returns (uint64 n, uint256 sum, uint256 average) {
        n = count[agentId];
        sum = total[agentId];
        average = n == 0 ? 0 : sum / n;
    }

    // --- ecrecover (no external deps) ---
    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (v < 27) v += 27;
        require(v == 27 || v == 28, "bad sig v");
        // reject the upper range of s to avoid signature malleability (EIP-2)
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "bad sig s");
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "invalid signature");
        return signer;
    }
}
