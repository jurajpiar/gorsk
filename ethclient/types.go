package ethclient

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
)

// rskHeader represents an RSK block header as returned by the RSK RPC.
// RSK headers have some fields that differ from standard Ethereum headers:
//   - minimumGasPrice instead of baseFeePerGas (EIP-1559)
//   - Additional merged mining fields (bitcoinMergedMining*)
//   - No withdrawalsRoot, blobGasUsed, excessBlobGas, parentBeaconBlockRoot
type rskHeader struct {
	ParentHash  *common.Hash      `json:"parentHash"`
	UncleHash   *common.Hash      `json:"sha3Uncles"`
	Coinbase    *common.Address   `json:"miner"`
	Root        *common.Hash      `json:"stateRoot"`
	TxHash      *common.Hash      `json:"transactionsRoot"`
	ReceiptHash *common.Hash      `json:"receiptsRoot"`
	Bloom       *types.Bloom      `json:"logsBloom"`
	Difficulty  *hexutil.Big      `json:"difficulty"`
	Number      *hexutil.Big      `json:"number"`
	GasLimit    *hexutil.Uint64   `json:"gasLimit"`
	GasUsed     *hexutil.Uint64   `json:"gasUsed"`
	Time        *hexutil.Uint64   `json:"timestamp"`
	Extra       *hexutil.Bytes    `json:"extraData"`
	MixDigest   *common.Hash      `json:"mixHash"`
	Nonce       *types.BlockNonce `json:"nonce"`

	// RSK-specific fields
	MinimumGasPrice *hexutil.Big    `json:"minimumGasPrice"`
	PaidFees        *hexutil.Big    `json:"paidFees,omitempty"`
	UncleCount      *hexutil.Uint64 `json:"uncleCount,omitempty"`

	// Merged mining fields (RSK-specific)
	BitcoinMergedMiningHeader              *hexutil.Bytes `json:"bitcoinMergedMiningHeader,omitempty"`
	BitcoinMergedMiningMerkleProof         *hexutil.Bytes `json:"bitcoinMergedMiningMerkleProof,omitempty"`
	BitcoinMergedMiningCoinbaseTransaction *hexutil.Bytes `json:"bitcoinMergedMiningCoinbaseTransaction,omitempty"`

	// Hash is included in the response but computed, not stored
	Hash *common.Hash `json:"hash"`
}

// ToGethHeader converts an rskHeader to a standard go-ethereum types.Header.
// This mapping allows RSK blocks to be used with code expecting Ethereum headers.
//
// Key mappings:
//   - MinimumGasPrice -> BaseFee (for EIP-1559 compatibility)
//   - Other fields map directly to their Ethereum equivalents
//
// Fields not present in RSK (like WithdrawalsHash, BlobGasUsed) are left as nil/zero.
func (h *rskHeader) ToGethHeader() *types.Header {
	header := &types.Header{}

	if h.ParentHash != nil {
		header.ParentHash = *h.ParentHash
	}
	if h.UncleHash != nil {
		header.UncleHash = *h.UncleHash
	}
	if h.Coinbase != nil {
		header.Coinbase = *h.Coinbase
	}
	if h.Root != nil {
		header.Root = *h.Root
	}
	if h.TxHash != nil {
		header.TxHash = *h.TxHash
	}
	if h.ReceiptHash != nil {
		header.ReceiptHash = *h.ReceiptHash
	}
	if h.Bloom != nil {
		header.Bloom = *h.Bloom
	}
	if h.Difficulty != nil {
		header.Difficulty = (*big.Int)(h.Difficulty)
	}
	if h.Number != nil {
		header.Number = (*big.Int)(h.Number)
	}
	if h.GasLimit != nil {
		header.GasLimit = uint64(*h.GasLimit)
	}
	if h.GasUsed != nil {
		header.GasUsed = uint64(*h.GasUsed)
	}
	if h.Time != nil {
		header.Time = uint64(*h.Time)
	}
	if h.Extra != nil {
		header.Extra = *h.Extra
	}
	if h.MixDigest != nil {
		header.MixDigest = *h.MixDigest
	}
	if h.Nonce != nil {
		header.Nonce = *h.Nonce
	}

	// Map RSK's minimumGasPrice to BaseFee for EIP-1559 compatibility.
	// This allows txmgr and other code expecting BaseFee to work correctly.
	// In RSK, minimumGasPrice serves a similar purpose to baseFee - it's the
	// minimum gas price accepted by the network.
	if h.MinimumGasPrice != nil {
		header.BaseFee = (*big.Int)(h.MinimumGasPrice)
	}

	// Note: The following Ethereum fields are not present in RSK:
	// - WithdrawalsHash (EIP-4895)
	// - BlobGasUsed (EIP-4844)
	// - ExcessBlobGas (EIP-4844)
	// - ParentBeaconRoot (EIP-4788)
	// - RequestsHash (EIP-7685)
	// These remain nil/zero in the returned header.

	return header
}

// rskTransaction represents transaction data as returned by RSK RPC.
// Used internally for transaction parsing.
type rskTransaction struct {
	BlockHash        *common.Hash    `json:"blockHash,omitempty"`
	BlockNumber      *hexutil.Big    `json:"blockNumber,omitempty"`
	From             *common.Address `json:"from,omitempty"`
	Gas              *hexutil.Uint64 `json:"gas"`
	GasPrice         *hexutil.Big    `json:"gasPrice"`
	Hash             *common.Hash    `json:"hash"`
	Input            *hexutil.Bytes  `json:"input"`
	Nonce            *hexutil.Uint64 `json:"nonce"`
	To               *common.Address `json:"to"`
	TransactionIndex *hexutil.Uint64 `json:"transactionIndex,omitempty"`
	Value            *hexutil.Big    `json:"value"`
	V                *hexutil.Big    `json:"v"`
	R                *hexutil.Big    `json:"r"`
	S                *hexutil.Big    `json:"s"`
}
