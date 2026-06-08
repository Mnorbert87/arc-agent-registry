// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IdentityRegistry
/// @notice An ERC-8004 aligned agent identity registry for Arc. Each agent is a
///         non-fungible token (ERC-721) whose tokenURI points at an Agent Card
///         (a JSON document, by convention served at
///         `https://<domain>/.well-known/agent-card.json`) describing the agent's
///         endpoints, capabilities, and payment details (x402).
///
///         The agentId is the ERC-721 tokenId. Ownership of the token is ownership
///         of the identity: only the owner can update the card or hand the identity
///         to another address. This is a compact, dependency-free ERC-721 so the
///         audit surface stays small.
///
/// @dev    Faithful to the ERC-8004 Identity Registry model (ERC-721 + URIStorage),
///         adapted for Arc testnet. Not the verbatim Ethereum mainnet bytecode.
contract IdentityRegistry {
    // --- ERC-721 metadata ---
    string public constant name = "Arc Agent Identity";
    string public constant symbol = "ARCAGENT";

    // --- state ---
    uint256 private _nextId = 1; // agentIds start at 1; 0 means "no agent"
    mapping(uint256 => address) private _owners;
    mapping(address => uint256) private _balances;
    mapping(uint256 => address) private _tokenApprovals;
    mapping(address => mapping(address => bool)) private _operatorApprovals;
    mapping(uint256 => string) private _tokenURIs;

    // --- events ---
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
    /// @notice Emitted when an agent registers or updates its card.
    event Registered(uint256 indexed agentId, address indexed owner, string tokenURI);

    // --- ERC-8004 surface ---

    /// @notice Register a new agent identity owned by the caller.
    /// @param tokenURI_ URI of the agent card (e.g. the agent's /.well-known/agent-card.json).
    /// @return agentId The newly minted agent id.
    function register(string calldata tokenURI_) external returns (uint256 agentId) {
        agentId = _nextId++;
        _owners[agentId] = msg.sender;
        unchecked {
            _balances[msg.sender] += 1;
        }
        _tokenURIs[agentId] = tokenURI_;
        emit Transfer(address(0), msg.sender, agentId);
        emit Registered(agentId, msg.sender, tokenURI_);
    }

    /// @notice Update the card URI of an existing agent. Owner only.
    function updateRegistration(uint256 agentId, string calldata tokenURI_) external {
        require(_owners[agentId] == msg.sender, "not agent owner");
        _tokenURIs[agentId] = tokenURI_;
        emit Registered(agentId, msg.sender, tokenURI_);
    }

    /// @notice Total number of agents registered so far.
    function agentCount() external view returns (uint256) {
        return _nextId - 1;
    }

    /// @notice True if an agent id has been registered.
    function exists(uint256 agentId) external view returns (bool) {
        return _owners[agentId] != address(0);
    }

    // --- ERC-721 reads ---

    function tokenURI(uint256 agentId) external view returns (string memory) {
        require(_owners[agentId] != address(0), "no such agent");
        return _tokenURIs[agentId];
    }

    function ownerOf(uint256 agentId) public view returns (address) {
        address owner = _owners[agentId];
        require(owner != address(0), "no such agent");
        return owner;
    }

    function balanceOf(address owner) external view returns (uint256) {
        require(owner != address(0), "zero address");
        return _balances[owner];
    }

    function getApproved(uint256 agentId) public view returns (address) {
        require(_owners[agentId] != address(0), "no such agent");
        return _tokenApprovals[agentId];
    }

    function isApprovedForAll(address owner, address operator) public view returns (bool) {
        return _operatorApprovals[owner][operator];
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        // ERC-165, ERC-721, ERC-721Metadata
        return interfaceId == 0x01ffc9a7 || interfaceId == 0x80ac58cd || interfaceId == 0x5b5e139f;
    }

    // --- ERC-721 writes ---

    function approve(address to, uint256 agentId) external {
        address owner = ownerOf(agentId);
        require(to != owner, "approve to owner");
        require(msg.sender == owner || isApprovedForAll(owner, msg.sender), "not authorized");
        _tokenApprovals[agentId] = to;
        emit Approval(owner, to, agentId);
    }

    function setApprovalForAll(address operator, bool approved) external {
        require(operator != msg.sender, "approve to caller");
        _operatorApprovals[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function transferFrom(address from, address to, uint256 agentId) public {
        require(_isApprovedOrOwner(msg.sender, agentId), "not owner nor approved");
        require(ownerOf(agentId) == from, "from is not owner");
        require(to != address(0), "transfer to zero");

        // clear approval
        delete _tokenApprovals[agentId];
        unchecked {
            _balances[from] -= 1;
            _balances[to] += 1;
        }
        _owners[agentId] = to;
        emit Transfer(from, to, agentId);
    }

    function _isApprovedOrOwner(address spender, uint256 agentId) internal view returns (bool) {
        address owner = ownerOf(agentId);
        return (spender == owner || _tokenApprovals[agentId] == spender || isApprovedForAll(owner, spender));
    }
}
