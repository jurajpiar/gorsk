# Rootstock Block Hash and Account Verifier

Rootstock uses a different trie (unified, binary) than Ethereum (separate hexary). The block header is also different. This makes it harder for external programs to verify block hashes, transaction roots, receipt roots, and account proofs. We port Rootstock's Trie, Transaction, TransactionReceipt, Block, BlockHeader and helper classes from Java to Go.

## Core Libraries (`rskblocks/`)

### Block & Transaction Verification

- `block_hashes_helper.go` - Transaction and receipt root computation
  - `GetTxTrieRoot(transactions)` - Compute transaction trie root
  - `CalculateReceiptsTrieRoot(receipts)` - Compute receipts trie root

- `block_header_hash_helper.go` - Block header hash computation
  - `ComputeBlockHash(input, config)` - Compute block hash from input data
  - `InputToBlockHeader(input, config)` - Convert input to BlockHeader struct
  - `ConfigForBlockNumber(blockNum, network)` - Get config for network/block

- `block_header.go` - BlockHeader struct and RLP encoding
- `transaction.go` - Transaction struct and RLP encoding
- `receipt.go` - TransactionReceipt struct and RLP encoding

### Account Proof Verification

- `proof_helper.go` - Merkle proof verification for accounts and storage
  - `NewProofVerifier()` - Create a new proof verifier
  - `VerifyAccountProof(stateRoot, address, proofNodes)` - Verify account existence
  - `VerifyStorageProof(stateRoot, address, storageKey, proofNodes)` - Verify storage values
  - `DecodeRLPProofNodes(proofNodesHex)` - Decode RLP-encoded proof nodes

## CLI Tools

Run all commands from the `gorsk` directory.

### Block Verification Tool

Verify transaction roots, receipt roots, and block hashes:

```bash
go run ./cmd/verify_roots/ <block_number>
```

### Account Proof Verification Tool

Verify `eth_getProof` responses:

```bash
# Verify EOA account proof
go run ./cmd/acct_verify_proof/ 0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826

# Verify contract with storage slot 0
go run ./cmd/acct_verify_proof/ 0x77045E71a7A2c50903d88e564cD72fab11e82051 0x0

# Verify multiple storage slots
go run ./cmd/acct_verify_proof/ <contract_address> 0x0,0x1,0x2
```

## Using the Go Library

### Block Hash Verification

```go
import "gorsk/rskblocks"

// Create input from hex strings (e.g., from RPC)
input, _ := rskblocks.NewBlockHeaderInputFromHex(
    parentHash, sha3Uncles, coinbase, stateRoot, txTrieRoot,
    receiptTrieRoot, logsBloom, difficulty, number, gasLimit,
    gasUsed, timestamp, extraData, paidFees, minimumGasPrice,
    uncleCount, ummRoot, txExecutionSublistsEdges,
)

// Get config for the block
config := rskblocks.ConfigForBlockNumber(blockNum, "regtest")

// Compute block hash
hash, _ := rskblocks.ComputeBlockHash(input, config)
```

### Account Proof Verification

```go
import (
    "gorsk/rskblocks"
    "github.com/ethereum/go-ethereum/common"
)

// Create verifier
verifier := rskblocks.NewProofVerifier()

// Verify account proof (proofNodesHex from eth_getProof response)
isValid, accountRLP, err := verifier.VerifyAccountProof(
    stateRoot,
    address,
    proofNodesHex,  // []string from RPC
)

// Verify storage proof
isValid, valueRLP, err := verifier.VerifyStorageProof(
    stateRoot,
    address,
    storageKey,
    storageProofHex,
)
```

## Key Differences from Ethereum

RSK uses a **binary trie** (not Ethereum's hexary MPT) and a **unified trie** for accounts, contracts, and storage:

1. **Single Trie**: Accounts, code, and storage all share the same trie
2. **Key Structure**:
   - Account: `0x00 + keccak256(address)[:10] + address`
   - Storage: `accountKey + 0x00 + keccak256(slot)[:10] + stripZeros(slot)`
   - Code: `accountKey + 0x80`
3. **Proof Order**: Nodes are ordered leaf-to-root (last node is state root)

## RSKIPs for Block Hash Computation

| RSKIP | Description |
|-------|-------------|
| **RSKIP-92** | Excludes merged mining merkle proof and coinbase from hash |
| **RSKIP-351** | V1 headers use extensionData instead of raw logsBloom. extensionHash = Keccak256(RLP([Keccak256(logsBloom), edgesBytes])) |
| **RSKIP-UMM** | ummRoot present (even if empty) for blocks after activation |
| **RSKIP-144** | TxExecutionSublistsEdges for parallel transaction execution |

## Encoding Details

- **gasLimit**: Stored as 4-byte array with leading zeros preserved
- **minimumGasPrice**: 0 encodes as single zero byte (0x00), not empty (0x80)
- **TxExecutionSublistsEdges**: Empty array `[]` is different from `nil` in extension hash

## Use Cases

1. **Light Clients**: Verify account balances without syncing full chain
2. **Cross-chain Bridges**: Prove state on RSK to another chain
3. **State Verification**: Trustlessly verify contract storage values
4. **Fraud Proofs**: Prove incorrect state transitions

## eth_getProof on RSK

> **Note**: The `eth_getProof` RPC is not part of rskj yet. There is a PR from Fede Jinich [PR-1519](https://github.com/rsksmart/rskj/pull/1519) that we've merged locally for testing.

Basic usage:

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

## Additional Examples

See `misc/account-proof-examples.md` for detailed examples including:
- EOA proof requests and responses
- Contract deployment for testing
- Storage slot calculations for mappings
- Response field reference
