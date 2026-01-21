# Examples for eth_getProof (EIP-1186)

The `eth_getProof` RPC method returns Merkle proofs for account state and storage values, enabling trustless verification without a full node.

This RPC command is not part of rskj yet. However, there is a pull request for it from Fede Jinich [PR-1519](https://github.com/rsksmart/rskj/pull/1519). We have merged that PR into our local node for testing.

## 1. EOA (Externally Owned Account) Proof

Get proof for a funded account:

```bash
curl -s -X POST http://localhost:4444 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_getProof",
    "params": ["0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826", [], "latest"],
    "id": 1
  }' | jq .
```

**Example Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "balance": "0xc9f2c9cd03307215522740000",
    "codeHash": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    "nonce": "0x2",
    "storageHash": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
    "accountProof": [
      "0xb0506aa18a79061073179c0a334a8f67e4e384f3651fb016af1ff9cd37e3760980cf028d0c9f2c9cd03307215522740000",
      "0xb8424c5841c5a8a5d708c9e2bbab3afac49dfed735fb66b7179e22cecd698f31560b79cea19d1f6247a1408aa4980c6e5abdd3e593c86aa298dfc0b341daad0aa1bcbf5d",
      "..."
    ],
    "storageProof": []
  }
}
```

**Key fields for EOAs:**
- `codeHash`: `0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470` (SHA3 of empty - indicates no code)
- `storageHash`: `0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421` (empty trie hash)

---

## 2. Contract Proof with Storage

### Step 1: Deploy a Simple Storage Contract

Create `SimpleStorage.sol`:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleStorage {
    uint256 public value;        // slot 0
    address public owner;        // slot 1
    mapping(uint256 => uint256) public data;  // slot 2 (base)
    
    constructor() {
        value = 42;
        owner = msg.sender;
        data[0] = 100;
        data[1] = 200;
    }
}
```

Deploy using Foundry:
```bash
forge create gorsk/misc/SimpleStorage.sol:SimpleStorage \
  --private-key c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4 \
  --rpc-url http://localhost:4444 \
  --legacy \
  --broadcast
```
Save or copy the deployed contract address below


### Step 2: Get Proof for Contract with Storage Slot 0



```bash
curl -s -X POST http://localhost:4444 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_getProof",
    "params": [
      "0x77045E71a7A2c50903d88e564cD72fab11e82051",
      ["0x0000000000000000000000000000000000000000000000000000000000000000"],
      "latest"
    ],
    "id": 1
  }' | jq .
```

**Example Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "balance": "0x0",
    "codeHash": "0xc10f4e2caad321ec73bc2f9fb53dc69f934417616ae7f04622fb43ecbd8a27b2",
    "nonce": "0x0",
    "storageHash": "0x4ac668a682701c5e73038c48163ed1dfb8e75d8f90cf0ad54cea2285a32a5e98",
    "accountProof": [
      "0xb86d5d6a205d860d29c7c42561e0f155069b234b6eb590bce176341b2a6db1cc7b80...",
      "..."
    ],
    "storageProof": [
      {
        "key": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "value": "0x000000000000000000000000000000000000000000000000000000000000002a",
        "proofs": [
          "0x8f50ff56a437b365522d8aa3580c002a",
          "..."
        ]
      }
    ]
  }
}
```

**Key observations:**
- `codeHash`: Different from EOA hash (contract has bytecode)
- `storageHash`: Different from empty hash (contract has storage)
- `storageProof[0].value`: `0x2a` = **42** (matches `value = 42` in constructor)

---

## 3. Storage Slot Calculations

For simple variables, slots are sequential:
- `uint256 public value` → slot 0
- `address public owner` → slot 1

For mappings, the slot is calculated as:
```
slot = keccak256(abi.encode(key, baseSlot))
```

Example for `data[0]` where `data` is at base slot 2:
```bash
cast keccak256 $(cast abi-encode "f(uint256,uint256)" 0 2)
# Result: 0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace
```

---

## Response Fields Reference

| Field | Description |
|-------|-------------|
| `balance` | Account balance in wei (hex) |
| `codeHash` | Keccak256 of account code (empty hash for EOAs) |
| `nonce` | Transaction count (hex) |
| `storageHash` | Root hash of storage trie |
| `accountProof` | Array of RLP-encoded trie nodes from state root to account |
| `storageProof` | Array of storage proofs for requested keys |
| `storageProof[].key` | Storage slot key |
| `storageProof[].value` | Storage value at that slot |
| `storageProof[].proofs` | RLP-encoded trie nodes from storage root to value |

---

## Go Verification Tool

The `gorsk` package provides Go implementations to verify RSK proofs.

### Using the CLI Tool

```bash
cd gorsk

# Verify EOA account proof
go run ./cmd/acct_verify_proof/ 0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826

# Verify contract with storage slot 0
go run ./cmd/acct_verify_proof/ 0x77045E71a7A2c50903d88e564cD72fab11e82051 0x0

# Verify multiple storage slots
go run ./cmd/acct_verify_proof/ <contract_address> 0x0,0x1,0x2 latest
```

### Using the Go Library

```go
import (
    "gorsk/rskblocks"
    "github.com/ethereum/go-ethereum/common"
)

// Create verifier
verifier := rskblocks.NewProofVerifier()

// Decode proof nodes from hex strings
proofNodes, _ := rskblocks.DecodeRLPProofNodes(accountProofHex)

// Verify account proof
result, _ := verifier.VerifyAccountProof(stateRoot, address, proofNodes)
if result.Valid {
    fmt.Println("Account value:", result.Value)
}

// Verify storage proof
storageResult, _ := verifier.VerifyStorageProof(
    stateRoot,
    contractAddress,
    storageKey,
    storageProofNodes,
)
if storageResult.Valid {
    fmt.Println("Storage value:", storageResult.Value)
}
```

### Key Differences from Ethereum

RSK uses a **binary trie** (not Ethereum's hexary MPT) and a **unified trie** for accounts, contracts, and storage:

1. **Single Trie**: Accounts, code, and storage all share the same trie
2. **Key Structure**:
   - Account: `0x00 + keccak256(address)[:10] + address`
   - Storage: `accountKey + 0x00 + keccak256(slot)[:10] + stripZeros(slot)`
   - Code: `accountKey + 0x80`
3. **Proof Order**: Nodes are ordered leaf-to-root (last node is state root)

---

## Use Cases

1. **Light Clients**: Verify account balances without syncing full chain
2. **Cross-chain Bridges**: Prove state on RSK to another chain
3. **State Verification**: Trustlessly verify contract storage values
4. **Fraud Proofs**: Prove incorrect state transitions
