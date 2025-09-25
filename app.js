// Anonymous Authorization System Frontend
// Contract Address: 0xd2Fa8CEeC790Dd7853818F1a22156e137265cA1B

// Initialize app when everything is loaded
let ethersLoadAttempts = 0;
const maxEthersLoadAttempts = 10;

function initializeApp() {
    // Check if ethers is loaded
    if (typeof ethers === 'undefined') {
        ethersLoadAttempts++;
        if (ethersLoadAttempts < maxEthersLoadAttempts) {
            console.log('Waiting for ethers.js to load... Attempt:', ethersLoadAttempts);
            setTimeout(initializeApp, 500);
            return;
        } else {
            console.error('Ethers.js failed to load after multiple attempts');
            document.body.innerHTML = '<div style="text-align: center; padding: 50px; color: red;"><h2>❌ Failed to Load Required Libraries</h2><p>Unable to load ethers.js from CDN. Please check your internet connection and try again.</p><button onclick="location.reload()" style="padding: 10px 20px; font-size: 16px; background: #667eea; color: white; border: none; border-radius: 5px; cursor: pointer;">Retry</button></div>';
            return;
        }
    }

    console.log('✅ Ethers.js v6 loaded successfully:', ethers.version);

    // Initialize the app
    try {
        window.app = new AnonymousAuthApp();
        console.log('✅ Anonymous Authorization System initialized successfully');
    } catch (error) {
        console.error('❌ Failed to initialize app:', error);
        document.getElementById('statusMessage').innerHTML = `
            <div class="status-content">
                <span>Failed to initialize application: ${error.message}</span>
                <button onclick="location.reload()" class="close-btn">Retry</button>
            </div>
        `;
        document.getElementById('statusMessage').className = 'status-message error';
        document.getElementById('statusMessage').classList.remove('hidden');
    }
}

// Start initialization when DOM is ready
document.addEventListener('DOMContentLoaded', initializeApp);

class AnonymousAuthApp {
    constructor() {
        this.contractAddress = '0xd2Fa8CEeC790Dd7853818F1a22156e137265cA1B';
        this.sepoliaChainId = '0xaa36a7'; // Sepolia testnet chain ID
        this.sepoliaConfig = {
            chainId: '0xaa36a7',
            chainName: 'Sepolia Testnet',
            nativeCurrency: {
                name: 'Sepolia ETH',
                symbol: 'ETH',
                decimals: 18
            },
            rpcUrls: ['https://sepolia.infura.io/v3/', 'https://rpc.sepolia.org'],
            blockExplorerUrls: ['https://sepolia.etherscan.io']
        };
        this.contractABI = [
            "function owner() view returns (address)",
            "function nextTokenId() view returns (uint32)",
            "function nextRequestId() view returns (uint32)",
            "function authorizedIssuers(address) view returns (bool)",
            "function issueAuthToken(address holder, uint8 authLevel, uint32 expiryTimestamp)",
            "function requestAuthorization(uint8 requestedLevel)",
            "function processAuthRequest(uint32 requestId, bool approve, uint32 expiryTimestamp)",
            "function verifyAccess(uint32 tokenId, uint8 resourceId, uint8 requiredLevel)",
            "function revokeToken(uint32 tokenId)",
            "function authorizeIssuer(address issuer)",
            "function revokeIssuer(address issuer)",
            "function getUserTokens(address user) view returns (uint32[])",
            "function getTokenInfo(uint32 tokenId) view returns (bool isActive, uint256 issueTime, address issuer)",
            "function getUserAccessHistoryCount(address user) view returns (uint256)",
            "function hasValidAuthorization(address user) view returns (bool)",
            "event AuthTokenIssued(uint32 indexed tokenId, address indexed holder)",
            "event AuthorizationRequested(uint32 indexed requestId, address indexed requester)",
            "event AccessAttempted(address indexed user, bool success)",
            "event TokenRevoked(uint32 indexed tokenId)",
            "event IssuerAuthorized(address indexed issuer)",
            "event IssuerRevoked(address indexed issuer)"
        ];

        this.provider = null;
        this.signer = null;
        this.contract = null;
        this.userAddress = null;
        this.isOwner = false;

        this.init();
    }

    async init() {
        console.log('🚀 Initializing Anonymous Authorization System...');

        // Show the main UI immediately
        this.showMainInterface();

        // Setup event listeners
        this.setupEventListeners();

        // Check for existing wallet connection
        await this.checkConnection();

        console.log('✅ UI initialization complete');
    }

    showMainInterface() {
        console.log('🖥️ Setting up main interface...');

        // Ensure main panels are visible
        const userPanel = document.getElementById('userPanel');
        const adminPanel = document.getElementById('adminPanel');
        const container = document.querySelector('.container');

        // Debug: Check if elements exist
        console.log('DOM Elements found:');
        console.log('- Container:', !!container);
        console.log('- User Panel:', !!userPanel);
        console.log('- Admin Panel:', !!adminPanel);

        if (container) {
            container.style.display = 'block';
            container.style.opacity = '1';
            console.log('✅ Main container visible');
        }

        if (userPanel) {
            userPanel.classList.remove('hidden');
            userPanel.style.display = 'block';
            console.log('✅ User panel visible');
        } else {
            console.error('❌ User panel not found!');
        }

        // Admin panel will be shown later if user is owner
        if (adminPanel) {
            console.log('📋 Admin panel ready (will show if user is owner)');
        } else {
            console.error('❌ Admin panel not found!');
        }

        // Show initial loading states
        this.showInitialLoadingStates();

        // Add a visible indicator that the app is ready
        this.showStatus('🚀 Anonymous Authorization System loaded successfully! Please connect your MetaMask wallet.', 'info');
    }

    showInitialLoadingStates() {
        // Show loading states for data that will be loaded
        const elements = [
            'userTokens',
            'accessHistory',
            'pendingRequests'
        ];

        elements.forEach(id => {
            const element = document.getElementById(id);
            if (element) {
                element.innerHTML = '<p class="loading">Ready to connect wallet...</p>';
            }
        });
    }

    setupEventListeners() {
        // Wallet connection
        document.getElementById('connectWallet').addEventListener('click', () => this.connectWallet());

        // Forms
        document.getElementById('issueTokenForm').addEventListener('submit', (e) => this.handleIssueToken(e));
        document.getElementById('authorizeIssuerForm').addEventListener('submit', (e) => this.handleAuthorizeIssuer(e));
        document.getElementById('requestAuthForm').addEventListener('submit', (e) => this.handleRequestAuth(e));
        document.getElementById('verifyAccessForm').addEventListener('submit', (e) => this.handleVerifyAccess(e));

        // Status message close
        document.getElementById('closeStatus').addEventListener('click', () => this.hideStatus());

        // Auto-hide status messages
        setTimeout(() => this.hideStatus(), 5000);
    }

    async checkConnection() {
        if (typeof window.ethereum !== 'undefined') {
            try {
                const accounts = await window.ethereum.request({ method: 'eth_accounts' });
                if (accounts.length > 0) {
                    await this.connectWallet();
                }
            } catch (error) {
                console.error('Error checking connection:', error);
            }
        } else {
            this.showStatus('MetaMask required. Please install MetaMask browser extension to continue.', 'error');
        }
    }

    async connectWallet() {
        try {
            // 1. Check for MetaMask
            if (typeof window.ethereum === 'undefined') {
                throw new Error('MetaMask not detected. Please install MetaMask to continue.');
            }

            this.showLoading(true);
            this.showStatus('Connecting to MetaMask...', 'info');

            // 2. Request account access
            await window.ethereum.request({ method: 'eth_requestAccounts' });

            // 3. Create provider and signer (ethers v6 syntax)
            this.provider = new ethers.BrowserProvider(window.ethereum);
            this.signer = await this.provider.getSigner();
            this.userAddress = await this.signer.getAddress();

            // 4. Network validation and switching
            await this.validateAndSwitchNetwork();

            // 5. Contract initialization
            this.contract = new ethers.Contract(this.contractAddress, this.contractABI, this.signer);

            // 6. Check if user is owner
            const ownerAddress = await this.contract.owner();
            this.isOwner = this.userAddress.toLowerCase() === ownerAddress.toLowerCase();

            // 7. Update state and UI
            await this.updateWalletUI();
            await this.loadUserData();

            this.showStatus('Connected to Sepolia! ✅', 'success');

            // Setup network change listeners
            window.ethereum.on('accountsChanged', () => window.location.reload());
            window.ethereum.on('chainChanged', () => window.location.reload());

        } catch (error) {
            console.error('Wallet connection error:', error);

            // Enhanced error handling for ethers v6
            let errorMessage = 'Connection failed';

            if (error.code === 4001) {
                errorMessage = 'User rejected the connection request';
            } else if (error.code === -32002) {
                errorMessage = 'MetaMask is already processing a request. Please check your wallet.';
            } else if (error.message?.includes('network')) {
                errorMessage = 'Network connection error. Please check your internet connection.';
            } else if (error.message?.includes('user rejected')) {
                errorMessage = 'User rejected the transaction';
            } else if (error.message) {
                errorMessage = error.message;
            }

            this.showStatus(`Connection failed: ${errorMessage}`, 'error');
        } finally {
            this.showLoading(false);
        }
    }

    async validateAndSwitchNetwork() {
        try {
            const currentChainId = await window.ethereum.request({ method: 'eth_chainId' });

            if (currentChainId !== this.sepoliaChainId) {
                this.showStatus('Switching to Sepolia network...', 'info');

                try {
                    // Try to switch to Sepolia
                    await window.ethereum.request({
                        method: 'wallet_switchEthereumChain',
                        params: [{ chainId: this.sepoliaChainId }],
                    });
                } catch (switchError) {
                    // If Sepolia is not added to MetaMask, add it
                    if (switchError.code === 4902) {
                        this.showStatus('Adding Sepolia network to MetaMask...', 'info');

                        await window.ethereum.request({
                            method: 'wallet_addEthereumChain',
                            params: [this.sepoliaConfig],
                        });
                    } else {
                        throw switchError;
                    }
                }
            }
        } catch (error) {
            throw new Error(`Network switching failed: ${error.message}`);
        }
    }

    async updateWalletUI() {
        const connectBtn = document.getElementById('connectWallet');
        const walletInfo = document.getElementById('walletInfo');
        const walletAddress = document.getElementById('walletAddress');
        const networkStatus = document.getElementById('networkStatus');
        const adminPanel = document.getElementById('adminPanel');

        if (this.userAddress) {
            connectBtn.classList.add('hidden');
            walletInfo.classList.remove('hidden');

            // Display shortened address
            const shortAddress = `${this.userAddress.slice(0, 6)}...${this.userAddress.slice(-4)}`;
            walletAddress.textContent = shortAddress;

            // Check network (ethers v6 syntax)
            const network = await this.provider.getNetwork();
            const chainId = Number(network.chainId);
            networkStatus.textContent = chainId === 11155111 ? 'Sepolia Testnet' : `Chain ID: ${chainId}`;

            // Show admin panel if user is owner
            if (this.isOwner) {
                adminPanel.classList.remove('hidden');
            }
        }
    }

    async loadUserData() {
        try {
            await this.loadUserTokens();
            await this.loadAccessHistory();

            if (this.isOwner) {
                await this.loadPendingRequests();
            }
        } catch (error) {
            console.error('Error loading user data:', error);
        }
    }

    async loadUserTokens() {
        try {
            const tokensContainer = document.getElementById('userTokens');

            // Check if the contract function exists and try to call it
            const tokenIds = await this.contract.getUserTokens(this.userAddress);

            if (tokenIds.length === 0) {
                tokensContainer.innerHTML = '<p class="loading">No authorization tokens found.</p>';
                return;
            }

            let tokensHTML = '';

            for (const tokenId of tokenIds) {
                try {
                    const tokenInfo = await this.contract.getTokenInfo(tokenId);
                    const level = 'ENCRYPTED'; // Since levels are encrypted in FHE

                    tokensHTML += `
                        <div class="token-item">
                            <div class="token-info">
                                <span class="token-id">Token #${tokenId}</span>
                                <span class="token-level level-encrypted">${level}</span>
                                <div class="token-status">
                                    Status: ${tokenInfo.isActive ? 'Active' : 'Inactive'}<br>
                                    Issued: ${new Date(Number(tokenInfo.issueTime) * 1000).toLocaleDateString()}
                                </div>
                            </div>
                            ${tokenInfo.isActive && this.isOwner ?
                                `<button class="btn btn-danger" onclick="app.revokeToken(${tokenId})">Revoke</button>` :
                                ''
                            }
                        </div>
                    `;
                } catch (tokenError) {
                    console.warn('Error loading token info for token', tokenId, ':', tokenError);
                    tokensHTML += `
                        <div class="token-item">
                            <div class="token-info">
                                <span class="token-id">Token #${tokenId}</span>
                                <span class="token-level level-encrypted">ENCRYPTED</span>
                                <div class="token-status">Status: Unknown</div>
                            </div>
                        </div>
                    `;
                }
            }

            tokensContainer.innerHTML = tokensHTML;
        } catch (error) {
            console.error('Error loading user tokens:', error);
            const tokensContainer = document.getElementById('userTokens');

            // More specific error messages
            if (error.message.includes('execution reverted')) {
                tokensContainer.innerHTML = '<p class="loading">No tokens found for this address.</p>';
            } else if (error.message.includes('CALL_EXCEPTION')) {
                tokensContainer.innerHTML = '<p class="loading">Contract not deployed or function not available.</p>';
            } else {
                tokensContainer.innerHTML = '<p class="loading">Error loading tokens. Please try again.</p>';
            }
        }
    }

    async loadAccessHistory() {
        try {
            const historyContainer = document.getElementById('accessHistory');
            const historyCount = await this.contract.getUserAccessHistoryCount(this.userAddress);

            const countNumber = Number(historyCount);

            if (countNumber === 0) {
                historyContainer.innerHTML = '<p class="loading">No access history found.</p>';
                return;
            }

            // For privacy reasons, we only show the count
            historyContainer.innerHTML = `
                <div class="history-item">
                    <div class="history-info">
                        <strong>Total Access Attempts: ${countNumber}</strong>
                        <div style="margin-top: 8px; font-size: 0.9rem; color: #718096;">
                            Detailed access logs are encrypted for privacy protection.
                        </div>
                    </div>
                </div>
            `;
        } catch (error) {
            console.error('Error loading access history:', error);
            const historyContainer = document.getElementById('accessHistory');

            // Better error handling
            if (error.message.includes('execution reverted')) {
                historyContainer.innerHTML = '<p class="loading">No access history available.</p>';
            } else if (error.message.includes('CALL_EXCEPTION')) {
                historyContainer.innerHTML = '<p class="loading">Access history function not available.</p>';
            } else {
                historyContainer.innerHTML = '<p class="loading">Unable to load access history.</p>';
            }
        }
    }

    async loadPendingRequests() {
        try {
            // Note: In a real implementation, you would need to track pending requests
            // This is a simplified version showing the concept
            const requestsContainer = document.getElementById('pendingRequests');
            requestsContainer.innerHTML = '<p class="loading">No pending requests found.</p>';
        } catch (error) {
            console.error('Error loading pending requests:', error);
        }
    }

    async handleIssueToken(event) {
        event.preventDefault();

        if (!this.contract) {
            this.showStatus('Please connect your wallet first', 'error');
            return;
        }

        try {
            this.showLoading(true);

            const holderAddress = document.getElementById('holderAddress').value;
            const authLevel = parseInt(document.getElementById('authLevel').value);
            const expiryDays = parseInt(document.getElementById('expiryDays').value);

            // Calculate expiry timestamp
            const expiryTimestamp = Math.floor(Date.now() / 1000) + (expiryDays * 24 * 60 * 60);

            const tx = await this.contract.issueAuthToken(holderAddress, authLevel, expiryTimestamp);
            const receipt = await tx.wait();

            console.log('Transaction confirmed:', receipt.hash);

            this.showStatus('Authorization token issued successfully!', 'success');
            document.getElementById('issueTokenForm').reset();

            if (holderAddress.toLowerCase() === this.userAddress.toLowerCase()) {
                await this.loadUserTokens();
            }

        } catch (error) {
            console.error('Error issuing token:', error);

            // Enhanced error handling for contract interactions
            let errorMessage = 'Failed to issue token';

            if (error.code === 'ACTION_REJECTED') {
                errorMessage = 'Transaction was rejected by user';
            } else if (error.code === 'INSUFFICIENT_FUNDS') {
                errorMessage = 'Insufficient funds for transaction';
            } else if (error.code === 'UNPREDICTABLE_GAS_LIMIT') {
                errorMessage = 'Transaction may fail. Please check contract parameters.';
            } else if (error.reason) {
                errorMessage = `Contract error: ${error.reason}`;
            } else if (error.message) {
                errorMessage = error.message;
            }

            this.showStatus(errorMessage, 'error');
        } finally {
            this.showLoading(false);
        }
    }

    async handleAuthorizeIssuer(event) {
        event.preventDefault();

        if (!this.contract) {
            this.showStatus('Please connect your wallet first', 'error');
            return;
        }

        try {
            this.showLoading(true);

            const issuerAddress = document.getElementById('issuerAddress').value;
            const tx = await this.contract.authorizeIssuer(issuerAddress);
            await tx.wait();

            this.showStatus('Issuer authorized successfully!', 'success');
            document.getElementById('authorizeIssuerForm').reset();

        } catch (error) {
            console.error('Error authorizing issuer:', error);
            this.showStatus(`Failed to authorize issuer: ${error.message}`, 'error');
        } finally {
            this.showLoading(false);
        }
    }

    async handleRequestAuth(event) {
        event.preventDefault();

        if (!this.contract) {
            this.showStatus('Please connect your wallet first', 'error');
            return;
        }

        try {
            this.showLoading(true);

            const requestLevel = parseInt(document.getElementById('requestLevel').value);
            const tx = await this.contract.requestAuthorization(requestLevel);
            await tx.wait();

            this.showStatus('Authorization request submitted successfully!', 'success');
            document.getElementById('requestAuthForm').reset();

        } catch (error) {
            console.error('Error requesting authorization:', error);
            this.showStatus(`Failed to request authorization: ${error.message}`, 'error');
        } finally {
            this.showLoading(false);
        }
    }

    async handleVerifyAccess(event) {
        event.preventDefault();

        if (!this.contract) {
            this.showStatus('Please connect your wallet first', 'error');
            return;
        }

        try {
            this.showLoading(true);

            const tokenId = parseInt(document.getElementById('tokenId').value);
            const resourceId = parseInt(document.getElementById('resourceId').value);
            const requiredLevel = parseInt(document.getElementById('requiredLevel').value);

            const tx = await this.contract.verifyAccess(tokenId, resourceId, requiredLevel);
            await tx.wait();

            this.showStatus('Access verification completed!', 'success');
            document.getElementById('verifyAccessForm').reset();
            await this.loadAccessHistory();

        } catch (error) {
            console.error('Error verifying access:', error);
            this.showStatus(`Access verification failed: ${error.message}`, 'error');
        } finally {
            this.showLoading(false);
        }
    }

    async revokeToken(tokenId) {
        if (!this.contract) {
            this.showStatus('Please connect your wallet first', 'error');
            return;
        }

        try {
            this.showLoading(true);

            const tx = await this.contract.revokeToken(tokenId);
            await tx.wait();

            this.showStatus('Token revoked successfully!', 'success');
            await this.loadUserTokens();

        } catch (error) {
            console.error('Error revoking token:', error);
            this.showStatus(`Failed to revoke token: ${error.message}`, 'error');
        } finally {
            this.showLoading(false);
        }
    }

    async getLevelName(tokenId) {
        // Since the actual level is encrypted, we return a generic representation
        // In a real implementation, this would require FHE decryption
        const levels = ['NONE', 'BASIC', 'PREMIUM', 'ADMIN'];
        return 'ENCRYPTED'; // Placeholder since actual level is encrypted
    }

    showStatus(message, type = 'info') {
        const statusMessage = document.getElementById('statusMessage');
        const statusText = document.getElementById('statusText');

        statusText.textContent = message;
        statusMessage.className = `status-message ${type}`;
        statusMessage.classList.remove('hidden');

        // Auto-hide after 5 seconds
        setTimeout(() => this.hideStatus(), 5000);
    }

    hideStatus() {
        document.getElementById('statusMessage').classList.add('hidden');
    }

    showLoading(show) {
        const overlay = document.getElementById('loadingOverlay');
        if (show) {
            overlay.classList.remove('hidden');
        } else {
            overlay.classList.add('hidden');
        }
    }

    // Utility function to format addresses
    formatAddress(address) {
        return `${address.slice(0, 6)}...${address.slice(-4)}`;
    }

    // Utility function to format timestamps
    formatTimestamp(timestamp) {
        return new Date(timestamp * 1000).toLocaleString();
    }
}

// App is initialized at the top of the file after ethers.js loads

// Global error handler
window.addEventListener('error', (event) => {
    console.error('Global error:', event.error);
});

// Handle unhandled promise rejections
window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
});