# Rootstock block hash verifier
Rootstock uses a different trie (unified, binary) than ethereum (separate hexary). The block header is also different. This makes it harder for external programs to verify block hashes, transaction roots and receipt roots. We port Rootstock's Trie, Transaction, TransactionReceipt, Block, BlockHeader and some helper classes from java to golang. 


### Core Libraries (gorsk/rskblocks/)

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

### Verification Tool

The verification tool is at `gorsk/cmd/verify_roots/main.go`. Run with:
```bash
go run ./cmd/verify_roots/ <block_number>
```

### Key RSKIPs for Block Hash Computation

- **RSKIP-92**: Excludes merged mining merkle proof and coinbase from hash computation
- **RSKIP-351**: V1 headers use extensionData instead of raw logsBloom
  - extensionHash = Keccak256(RLP([Keccak256(logsBloom), edgesBytes]))
- **RSKIP-UMM**: ummRoot present (even if empty) for blocks after activation
- **RSKIP-144**: TxExecutionSublistsEdges for parallel transaction execution

### Encoding Details

- gasLimit: stored as 4-byte array with leading zeros preserved
- minimumGasPrice: 0 encodes as single zero byte (0x00), not empty (0x80)
- TxExecutionSublistsEdges: empty array [] is different from null in extension hash



