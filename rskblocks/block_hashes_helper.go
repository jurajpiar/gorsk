package rskblocks

import (
	"gorsk/rsktrie"

	"github.com/ethereum/go-ethereum/rlp"
)

// BlockHashesHelper provides methods to calculate transaction and receipt trie roots.
// Ported from co.rsk.core.bc.BlockHashesHelper.java
type BlockHashesHelper struct{}

// CalculateReceiptsTrieRoot calculates the root hash of the receipts trie.
// Corresponds to calculateReceiptsTrieRoot(List<TransactionReceipt> receipts, boolean isRskip126Enabled)
// NOTE: We assume isRskip126Enabled is always TRUE, as requested.
func CalculateReceiptsTrieRoot(receipts []*TransactionReceipt) []byte {
	trie := CalculateReceiptsTrieFor(receipts)
	// if (isRskip126Enabled) {
	return trie.GetHash()
	// }
	// return trie.getHashOrchid(false).getBytes(); // Skipped as per instructions
}

// CalculateReceiptsTrieFor builds a Trie containing the given receipts.
func CalculateReceiptsTrieFor(receipts []*TransactionReceipt) *rsktrie.Trie {
	receiptsTrie := rsktrie.NewTrie(nil)
	for i, receipt := range receipts {
		key, _ := rlp.EncodeToBytes(uint64(i))
		encodedReceipt, _ := rlp.EncodeToBytes(receipt)
		receiptsTrie = receiptsTrie.Put(key, encodedReceipt)
	}
	return receiptsTrie
}

// GetTxTrieRoot calculates the root hash of the transactions trie.
// Corresponds to getTxTrieRoot(List<Transaction> transactions, boolean isRskip126Enabled)
// NOTE: We assume isRskip126Enabled is always TRUE, as requested.
func GetTxTrieRoot(transactions []*Transaction) []byte {
	trie := GetTxTrieFor(transactions)
	// if (isRskip126Enabled) {
	return trie.GetHash()
	// }
	// return trie.getHashOrchid(false).getBytes(); // Skipped as per instructions
}

// GetTxTrieFor builds a Trie containing the given transactions.
func GetTxTrieFor(transactions []*Transaction) *rsktrie.Trie {
	txsState := rsktrie.NewTrie(nil)
	if transactions == nil {
		return txsState
	}

	for i, tx := range transactions {
		key, _ := rlp.EncodeToBytes(uint64(i))
		encodedTx, _ := rlp.EncodeToBytes(tx)
		txsState = txsState.Put(key, encodedTx)
	}

	return txsState
}
