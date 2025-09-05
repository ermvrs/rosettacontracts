#!/bin/bash

# Exit on any error
set -e

echo "Starting Rosetta Contracts deployment process..."
echo "=========================================="

# Step 1: Clean previous build artifacts
echo "Step 1: Cleaning previous build artifacts..."
scarb clean

# Step 2: Build contracts
echo "Step 2: Building contracts..."
scarb build

# Step 3: Declare RosettaAccount contract
echo "Step 3: Declaring RosettaAccount contract..."
ACCOUNT_DECLARE_OUTPUT=$(sncast --account sepolia_deployer declare --network sepolia --contract-name RosettaAccount 2>&1)
echo "$ACCOUNT_DECLARE_OUTPUT"

# Extract account class hash from output
ACCOUNT_CLASS_HASH=$(echo "$ACCOUNT_DECLARE_OUTPUT" | grep "Class Hash:" | awk '{print $3}')
if [ -z "$ACCOUNT_CLASS_HASH" ]; then
    # Try alternative format for already declared contracts
    ACCOUNT_CLASS_HASH=$(echo "$ACCOUNT_DECLARE_OUTPUT" | grep -oP 'already declared with class hash: \K0x[0-9a-fA-F]+')
fi

if [ -z "$ACCOUNT_CLASS_HASH" ]; then
    echo "Error: Failed to extract Account class hash"
    exit 1
fi

echo "Account class hash: $ACCOUNT_CLASS_HASH"

# Step 4: Declare Rosettanet contract
echo "Step 4: Declaring Rosettanet contract..."
ROSETTANET_DECLARE_OUTPUT=$(sncast --account sepolia_deployer declare --network sepolia --contract-name Rosettanet 2>&1)
echo "$ROSETTANET_DECLARE_OUTPUT"

# Extract Rosettanet class hash from output
ROSETTANET_CLASS_HASH=$(echo "$ROSETTANET_DECLARE_OUTPUT" | grep "Class Hash:" | awk '{print $3}')
if [ -z "$ROSETTANET_CLASS_HASH" ]; then
    # Try alternative format for already declared contracts
    ROSETTANET_CLASS_HASH=$(echo "$ROSETTANET_DECLARE_OUTPUT" | grep -oP 'already declared with class hash: \K0x[0-9a-fA-F]+')
fi

if [ -z "$ROSETTANET_CLASS_HASH" ]; then
    echo "Error: Failed to extract Rosettanet class hash"
    exit 1
fi

echo "Rosettanet class hash: $ROSETTANET_CLASS_HASH"

# Step 5: Deploy Rosettanet contract
echo "Step 5: Deploying Rosettanet contract..."
echo "Constructor parameters:"
echo "  - Account class hash: $ACCOUNT_CLASS_HASH"
echo "  - Admin address: 0x061D2D0E093B92116632A5068Ce683d051E2Ada4ACddf948bA77ec2Fed9786d6"
echo "  - Fee token: 0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d"

DEPLOY_OUTPUT=$(sncast --account sepolia_deployer deploy --network sepolia --class-hash "$ROSETTANET_CLASS_HASH" --constructor-calldata "$ACCOUNT_CLASS_HASH" 0x061D2D0E093B92116632A5068Ce683d051E2Ada4ACddf948bA77ec2Fed9786d6 0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d 2>&1)
echo "$DEPLOY_OUTPUT"

# Extract deployed contract address
CONTRACT_ADDRESS=$(echo "$DEPLOY_OUTPUT" | grep -oP 'contract_address: \K0x[0-9a-fA-F]+')

if [ -z "$CONTRACT_ADDRESS" ]; then
    echo "Error: Failed to extract contract address"
    exit 1
fi

echo "=========================================="
echo "Deployment completed successfully!"
echo "Rosettanet contract address: $CONTRACT_ADDRESS"
echo "Account class hash: $ACCOUNT_CLASS_HASH"
echo "Rosettanet class hash: $ROSETTANET_CLASS_HASH"