const { ethers } = require("hardhat");

async function main() {
  console.log("Deploying Anonymous Authorization System...");

  // Get the deployer account
  const [deployer] = await ethers.getSigners();
  console.log("Deploying contracts with the account:", deployer.address);

  // Check account balance
  const balance = await ethers.provider.getBalance(deployer.address);
  console.log("Account balance:", ethers.formatEther(balance));

  // Deploy the contract
  const AnonymousAuthorizationSystem = await ethers.getContractFactory("AnonymousAuthorizationSystem");

  console.log("Deploying AnonymousAuthorizationSystem contract...");
  const authSystem = await AnonymousAuthorizationSystem.deploy();

  await authSystem.waitForDeployment();

  const contractAddress = await authSystem.getAddress();
  console.log("AnonymousAuthorizationSystem deployed to:", contractAddress);

  // Verify deployment
  console.log("Verifying deployment...");
  const owner = await authSystem.owner();
  const nextTokenId = await authSystem.nextTokenId();
  const nextRequestId = await authSystem.nextRequestId();

  console.log("Contract owner:", owner);
  console.log("Next token ID:", nextTokenId.toString());
  console.log("Next request ID:", nextRequestId.toString());

  // Save deployment info
  const deploymentInfo = {
    contractAddress: contractAddress,
    deployer: deployer.address,
    network: hre.network.name,
    deploymentTime: new Date().toISOString(),
    blockNumber: await ethers.provider.getBlockNumber()
  };

  console.log("\n=== Deployment Summary ===");
  console.log("Contract Address:", deploymentInfo.contractAddress);
  console.log("Deployer:", deploymentInfo.deployer);
  console.log("Network:", deploymentInfo.network);
  console.log("Block Number:", deploymentInfo.blockNumber);
  console.log("Deployment Time:", deploymentInfo.deploymentTime);

  console.log("\n=== Contract Features ===");
  console.log("✓ Anonymous authorization tokens with FHE encryption");
  console.log("✓ Privacy-preserving access control");
  console.log("✓ Encrypted authorization levels and expiry times");
  console.log("✓ Anonymous authorization requests");
  console.log("✓ Privacy-preserving access analytics");
  console.log("✓ Multi-level authorization system");

  console.log("\n=== Usage Instructions ===");
  console.log("1. Authorize issuers using authorizeIssuer()");
  console.log("2. Issue authorization tokens with issueAuthToken()");
  console.log("3. Users can request authorization with requestAuthorization()");
  console.log("4. Verify access with verifyAccess()");
  console.log("5. View encrypted analytics with privacy preservation");

  return contractAddress;
}

main()
  .then((contractAddress) => {
    console.log("\nDeployment completed successfully!");
    process.exit(0);
  })
  .catch((error) => {
    console.error("Deployment failed:", error);
    process.exit(1);
  });