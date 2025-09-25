// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { FHE, euint8, euint32, ebool } from "@fhevm/solidity/lib/FHE.sol";
import { SepoliaConfig } from "@fhevm/solidity/config/ZamaConfig.sol";

contract AnonymousAuthorizationSystem is SepoliaConfig {

    address public owner;
    uint32 public nextTokenId;
    uint32 public nextRequestId;

    // Authorization levels
    enum AuthLevel { NONE, BASIC, PREMIUM, ADMIN }

    struct PrivateAuthToken {
        euint8 encryptedLevel;     // Encrypted authorization level
        euint32 encryptedExpiry;   // Encrypted expiry timestamp
        bool isActive;
        uint256 issueTime;
        address issuer;
    }

    struct AuthorizationRequest {
        address requester;
        euint8 encryptedRequestLevel;  // Requested level (encrypted)
        uint256 timestamp;
        bool processed;
        bool approved;
        uint32 tokenId;
    }

    struct AccessAttempt {
        euint8 encryptedResource;     // Resource ID (encrypted)
        euint8 encryptedRequiredLevel; // Required level (encrypted)
        uint256 timestamp;
        bool success;
    }

    // Mappings
    mapping(uint32 => PrivateAuthToken) public authTokens;
    mapping(address => uint32[]) public userTokens;
    mapping(uint32 => AuthorizationRequest) public authRequests;
    mapping(address => AccessAttempt[]) public userAccessHistory;
    mapping(address => bool) public authorizedIssuers;

    // Privacy-preserving counters
    mapping(address => euint32) private encryptedAccessCounts;
    mapping(uint8 => euint32) private encryptedResourceAccess;

    // Events
    event AuthTokenIssued(uint32 indexed tokenId, address indexed holder);
    event AuthorizationRequested(uint32 indexed requestId, address indexed requester);
    event AccessAttempted(address indexed user, bool success);
    event TokenRevoked(uint32 indexed tokenId);
    event IssuerAuthorized(address indexed issuer);
    event IssuerRevoked(address indexed issuer);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    modifier onlyAuthorizedIssuer() {
        require(authorizedIssuers[msg.sender] || msg.sender == owner, "Not authorized issuer");
        _;
    }

    modifier validTokenId(uint32 tokenId) {
        require(tokenId < nextTokenId, "Invalid token ID");
        require(authTokens[tokenId].isActive, "Token not active");
        _;
    }

    constructor() {
        owner = msg.sender;
        nextTokenId = 1;
        nextRequestId = 1;
        authorizedIssuers[owner] = true;
    }

    // Issue a new anonymous authorization token
    function issueAuthToken(
        address holder,
        uint8 authLevel,
        uint32 expiryTimestamp
    ) external onlyAuthorizedIssuer {
        require(holder != address(0), "Invalid holder address");
        require(authLevel <= uint8(AuthLevel.ADMIN), "Invalid authorization level");
        require(expiryTimestamp > block.timestamp, "Invalid expiry time");

        // Encrypt the authorization data
        euint8 encryptedLevel = FHE.asEuint8(authLevel);
        euint32 encryptedExpiry = FHE.asEuint32(expiryTimestamp);

        uint32 tokenId = nextTokenId++;

        authTokens[tokenId] = PrivateAuthToken({
            encryptedLevel: encryptedLevel,
            encryptedExpiry: encryptedExpiry,
            isActive: true,
            issueTime: block.timestamp,
            issuer: msg.sender
        });

        userTokens[holder].push(tokenId);

        // Set ACL permissions
        FHE.allowThis(encryptedLevel);
        FHE.allowThis(encryptedExpiry);
        FHE.allow(encryptedLevel, holder);
        FHE.allow(encryptedExpiry, holder);

        emit AuthTokenIssued(tokenId, holder);
    }

    // Request authorization upgrade (privacy-preserving)
    function requestAuthorization(uint8 requestedLevel) external {
        require(requestedLevel <= uint8(AuthLevel.ADMIN), "Invalid level");

        // Encrypt the requested level
        euint8 encryptedRequestLevel = FHE.asEuint8(requestedLevel);

        uint32 requestId = nextRequestId++;

        authRequests[requestId] = AuthorizationRequest({
            requester: msg.sender,
            encryptedRequestLevel: encryptedRequestLevel,
            timestamp: block.timestamp,
            processed: false,
            approved: false,
            tokenId: 0
        });

        // Set ACL permissions
        FHE.allowThis(encryptedRequestLevel);

        emit AuthorizationRequested(requestId, msg.sender);
    }

    // Process authorization request (admin function)
    function processAuthRequest(
        uint32 requestId,
        bool approve,
        uint32 expiryTimestamp
    ) external onlyAuthorizedIssuer {
        require(requestId < nextRequestId, "Invalid request ID");
        require(!authRequests[requestId].processed, "Already processed");

        AuthorizationRequest storage request = authRequests[requestId];
        request.processed = true;
        request.approved = approve;

        if (approve) {
            // Issue token using async decryption to get the requested level
            bytes32[] memory cts = new bytes32[](1);
            cts[0] = FHE.toBytes32(request.encryptedRequestLevel);

            // Store request details for callback
            _pendingRequests[requestId] = PendingRequest({
                holder: request.requester,
                expiryTimestamp: expiryTimestamp,
                requestId: requestId
            });

            FHE.requestDecryption(cts, this.processAuthCallback.selector);
        }
    }

    struct PendingRequest {
        address holder;
        uint32 expiryTimestamp;
        uint32 requestId;
    }

    mapping(uint32 => PendingRequest) private _pendingRequests;

    // Callback for processing authorization requests
    function processAuthCallback(
        uint256 requestId,
        bytes memory cleartexts,
        bytes memory decryptionProof
    ) external {
        // Verify signatures with the v0.8.0 signature
        FHE.checkSignatures(requestId, cleartexts, decryptionProof);

        // Decode the decrypted authorization level
        (uint8 requestedLevel) = abi.decode(cleartexts, (uint8));

        uint32 reqId = uint32(requestId);
        PendingRequest storage pending = _pendingRequests[reqId];

        // Issue the token with decrypted level
        euint8 encryptedLevel = FHE.asEuint8(requestedLevel);
        euint32 encryptedExpiry = FHE.asEuint32(pending.expiryTimestamp);

        uint32 tokenId = nextTokenId++;

        authTokens[tokenId] = PrivateAuthToken({
            encryptedLevel: encryptedLevel,
            encryptedExpiry: encryptedExpiry,
            isActive: true,
            issueTime: block.timestamp,
            issuer: msg.sender
        });

        userTokens[pending.holder].push(tokenId);
        authRequests[reqId].tokenId = tokenId;

        // Set ACL permissions
        FHE.allowThis(encryptedLevel);
        FHE.allowThis(encryptedExpiry);
        FHE.allow(encryptedLevel, pending.holder);
        FHE.allow(encryptedExpiry, pending.holder);

        delete _pendingRequests[reqId];

        emit AuthTokenIssued(tokenId, pending.holder);
    }

    // Verify access with privacy preservation
    function verifyAccess(
        uint32 tokenId,
        uint8 resourceId,
        uint8 requiredLevel
    ) external validTokenId(tokenId) {
        PrivateAuthToken storage token = authTokens[tokenId];

        // Encrypt the required level and resource ID
        euint8 encryptedRequiredLevel = FHE.asEuint8(requiredLevel);
        euint8 encryptedResource = FHE.asEuint8(resourceId);
        euint32 encryptedCurrentTime = FHE.asEuint32(uint32(block.timestamp));

        // Check if token level >= required level (FHE comparison)
        ebool hasPermission = FHE.ge(token.encryptedLevel, encryptedRequiredLevel);

        // Check if token is not expired
        ebool notExpired = FHE.ge(token.encryptedExpiry, encryptedCurrentTime);

        // Both conditions must be true
        ebool accessGranted = FHE.and(hasPermission, notExpired);

        // Record access attempt (encrypted)
        AccessAttempt memory attempt = AccessAttempt({
            encryptedResource: encryptedResource,
            encryptedRequiredLevel: encryptedRequiredLevel,
            timestamp: block.timestamp,
            success: false  // Will be updated via callback
        });

        userAccessHistory[msg.sender].push(attempt);

        // Update privacy-preserving counters
        encryptedAccessCounts[msg.sender] = FHE.add(encryptedAccessCounts[msg.sender], FHE.asEuint32(1));
        encryptedResourceAccess[resourceId] = FHE.add(encryptedResourceAccess[resourceId], FHE.asEuint32(1));

        // Set ACL permissions
        FHE.allowThis(encryptedRequiredLevel);
        FHE.allowThis(encryptedResource);
        FHE.allowThis(accessGranted);
        FHE.allow(accessGranted, msg.sender);

        // For demonstration, we emit with encrypted result
        // In practice, you might use async decryption for the result
        emit AccessAttempted(msg.sender, false); // Placeholder
    }

    // Revoke authorization token
    function revokeToken(uint32 tokenId) external onlyAuthorizedIssuer validTokenId(tokenId) {
        authTokens[tokenId].isActive = false;
        emit TokenRevoked(tokenId);
    }

    // Authorize new issuer
    function authorizeIssuer(address issuer) external onlyOwner {
        require(issuer != address(0), "Invalid issuer address");
        authorizedIssuers[issuer] = true;
        emit IssuerAuthorized(issuer);
    }

    // Revoke issuer authorization
    function revokeIssuer(address issuer) external onlyOwner {
        require(issuer != owner, "Cannot revoke owner");
        authorizedIssuers[issuer] = false;
        emit IssuerRevoked(issuer);
    }

    // Get user's active tokens
    function getUserTokens(address user) external view returns (uint32[] memory) {
        return userTokens[user];
    }

    // Get token information (without revealing encrypted data)
    function getTokenInfo(uint32 tokenId) external view validTokenId(tokenId) returns (
        bool isActive,
        uint256 issueTime,
        address issuer
    ) {
        PrivateAuthToken storage token = authTokens[tokenId];
        return (token.isActive, token.issueTime, token.issuer);
    }

    // Get user's access history count
    function getUserAccessHistoryCount(address user) external view returns (uint256) {
        return userAccessHistory[user].length;
    }

    // Get encrypted access count for privacy-preserving analytics
    function getEncryptedAccessCount(address user) external view returns (euint32) {
        require(msg.sender == user || msg.sender == owner, "Unauthorized");
        return encryptedAccessCounts[user];
    }

    // Get encrypted resource access count
    function getEncryptedResourceAccess(uint8 resourceId) external view onlyAuthorizedIssuer returns (euint32) {
        return encryptedResourceAccess[resourceId];
    }

    // Emergency functions
    function pause() external onlyOwner {
        // Implementation for pausing contract
    }

    function unpause() external onlyOwner {
        // Implementation for unpausing contract
    }

    // Check if user has any valid authorization (privacy-preserving)
    function hasValidAuthorization(address user) external view returns (bool) {
        uint32[] memory tokens = userTokens[user];
        for (uint i = 0; i < tokens.length; i++) {
            if (authTokens[tokens[i]].isActive) {
                return true;
            }
        }
        return false;
    }
}