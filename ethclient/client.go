// Package ethclient provides an RSK-compatible Ethereum client that implements
// the ETHBackend interface from op-service/txmgr.
//
// RSK (Rootstock) has several key differences from standard Ethereum:
//   - No EIP-1559: Uses legacy gas pricing (gasPrice) instead of baseFee + priorityFee
//   - No blob transactions: Doesn't support EIP-4844
//   - Different header structure: Contains minimumGasPrice instead of baseFee
//   - Legacy transactions only: All transactions must use the legacy format
package ethclient

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
)

var (
	// ErrBlobsNotSupported is returned when blob-related methods are called.
	// RSK does not support EIP-4844 blob transactions.
	ErrBlobsNotSupported = errors.New("RSK does not support blob transactions")
)

// Client implements the ETHBackend interface for RSK nodes.
// It handles the differences between RSK and standard Ethereum RPC.
type Client struct {
	c *rpc.Client
}

// Dial connects to an RSK node at the given URL.
func Dial(rawurl string) (*Client, error) {
	return DialContext(context.Background(), rawurl)
}

// DialContext connects to an RSK node at the given URL with context.
func DialContext(ctx context.Context, rawurl string) (*Client, error) {
	c, err := rpc.DialContext(ctx, rawurl)
	if err != nil {
		return nil, err
	}
	return NewClient(c), nil
}

// NewClient creates a new Client from an existing RPC client.
func NewClient(c *rpc.Client) *Client {
	return &Client{c: c}
}

// Close closes the underlying RPC connection.
func (c *Client) Close() {
	c.c.Close()
}

// Client returns the underlying RPC client.
func (c *Client) Client() *rpc.Client {
	return c.c
}

// BlockNumber returns the most recent block number.
func (c *Client) BlockNumber(ctx context.Context) (uint64, error) {
	var result hexutil.Uint64
	err := c.c.CallContext(ctx, &result, "eth_blockNumber")
	return uint64(result), err
}

// HeaderByNumber returns a block header from the current canonical chain.
// If number is nil, the latest known block header is returned.
//
// RSK headers contain minimumGasPrice instead of baseFee. This method
// maps minimumGasPrice to the BaseFee field for compatibility.
func (c *Client) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	var raw rskHeader
	err := c.c.CallContext(ctx, &raw, "eth_getBlockByNumber", toBlockNumArg(number), false)
	if err != nil {
		return nil, err
	}
	if raw.Number == nil {
		return nil, ethereum.NotFound
	}
	return raw.ToGethHeader(), nil
}

// TransactionReceipt returns the receipt of a transaction by transaction hash.
// Note that the receipt is not available for pending transactions.
func (c *Client) TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
	var r *types.Receipt
	err := c.c.CallContext(ctx, &r, "eth_getTransactionReceipt", txHash)
	if err == nil && r == nil {
		return nil, ethereum.NotFound
	}
	return r, err
}

// SendTransaction injects a signed transaction into the pending pool for execution.
//
// RSK only supports legacy transactions (type 0). If an EIP-1559 (type 2) or
// other typed transaction is passed, this method converts it to a legacy
// transaction format before sending. The GasFeeCap is used as the GasPrice
// for legacy transactions.
//
// IMPORTANT: The transaction must already be signed. This method re-encodes
// the transaction in legacy RLP format but preserves the signature.
//
// Note: RSK may compute a different transaction hash than go-ethereum.
// Use SendTransactionReturnHash to get the actual hash returned by the RSK node.
func (c *Client) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	_, err := c.SendTransactionReturnHash(ctx, tx)
	return err
}

// SendTransactionReturnHash sends a transaction and returns the hash as computed by RSK.
// This is important because RSK may use a different hash algorithm than go-ethereum.
func (c *Client) SendTransactionReturnHash(ctx context.Context, tx *types.Transaction) (common.Hash, error) {
	// Convert to legacy transaction if needed
	legacyTx, err := toLegacyTransaction(tx)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to convert to legacy transaction: %w", err)
	}

	data, err := legacyTx.MarshalBinary()
	if err != nil {
		return common.Hash{}, err
	}

	// Capture the hash returned by RSK
	var rskHash common.Hash
	err = c.c.CallContext(ctx, &rskHash, "eth_sendRawTransaction", hexutil.Encode(data))
	if err != nil {
		return common.Hash{}, err
	}

	// Log if there's a hash mismatch (useful for debugging)
	localHash := legacyTx.Hash()
	if rskHash != localHash {
		// This is expected - RSK may compute hashes differently
		// The caller should use rskHash for receipt queries
		_ = localHash // Suppress unused warning; we're just noting the difference
	}

	return rskHash, nil
}

// toLegacyTransaction converts any transaction type to a legacy transaction.
// For EIP-1559 transactions, it uses GasFeeCap as the GasPrice.
// For legacy transactions, it returns them unchanged.
func toLegacyTransaction(tx *types.Transaction) (*types.Transaction, error) {
	// If already legacy, return as-is
	if tx.Type() == types.LegacyTxType {
		return tx, nil
	}

	// Get the signature values
	v, r, s := tx.RawSignatureValues()

	// Determine the gas price to use
	// For EIP-1559, use GasFeeCap (maxFeePerGas) as gasPrice
	// This ensures we're willing to pay up to that amount
	gasPrice := tx.GasPrice()
	if tx.Type() == types.DynamicFeeTxType {
		gasPrice = tx.GasFeeCap()
	}

	// Create legacy transaction with the same parameters
	legacyTxData := &types.LegacyTx{
		Nonce:    tx.Nonce(),
		GasPrice: gasPrice,
		Gas:      tx.Gas(),
		To:       tx.To(),
		Value:    tx.Value(),
		Data:     tx.Data(),
		V:        v,
		R:        r,
		S:        s,
	}

	return types.NewTx(legacyTxData), nil
}

// CallContract executes a message call transaction, which is directly executed
// in the VM of the node, but never mined into the blockchain.
//
// blockNumber selects the block height at which the call runs. It can be nil,
// in which case the code is taken from the latest known block.
func (c *Client) CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	var hex hexutil.Bytes
	err := c.c.CallContext(ctx, &hex, "eth_call", toCallArg(msg), toBlockNumArg(blockNumber))
	if err != nil {
		return nil, err
	}
	return hex, nil
}

// SuggestGasTipCap retrieves the currently suggested gas tip cap.
//
// Since RSK doesn't support EIP-1559, this returns the result of eth_gasPrice.
// The returned value can be used as the gasPrice for legacy transactions.
func (c *Client) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	var hex hexutil.Big
	if err := c.c.CallContext(ctx, &hex, "eth_gasPrice"); err != nil {
		return nil, err
	}
	return (*big.Int)(&hex), nil
}

// SuggestGasPrice retrieves the currently suggested gas price to allow a timely
// execution of a transaction.
func (c *Client) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	var hex hexutil.Big
	if err := c.c.CallContext(ctx, &hex, "eth_gasPrice"); err != nil {
		return nil, err
	}
	return (*big.Int)(&hex), nil
}

// BlobBaseFee returns an error because RSK doesn't support blob transactions.
func (c *Client) BlobBaseFee(ctx context.Context) (*big.Int, error) {
	return nil, ErrBlobsNotSupported
}

// NonceAt returns the account nonce of the given account.
// The block number can be nil, in which case the nonce is taken from the latest known block.
func (c *Client) NonceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (uint64, error) {
	var result hexutil.Uint64
	err := c.c.CallContext(ctx, &result, "eth_getTransactionCount", account, toBlockNumArg(blockNumber))
	return uint64(result), err
}

// PendingNonceAt returns the account nonce of the given account in the pending state.
// This is the nonce that should be used for the next transaction.
func (c *Client) PendingNonceAt(ctx context.Context, account common.Address) (uint64, error) {
	var result hexutil.Uint64
	err := c.c.CallContext(ctx, &result, "eth_getTransactionCount", account, "pending")
	return uint64(result), err
}

// EstimateGas tries to estimate the gas needed to execute a specific transaction
// based on the current state of the backend blockchain.
func (c *Client) EstimateGas(ctx context.Context, msg ethereum.CallMsg) (uint64, error) {
	var hex hexutil.Uint64
	err := c.c.CallContext(ctx, &hex, "eth_estimateGas", toCallArg(msg))
	if err != nil {
		return 0, err
	}
	return uint64(hex), nil
}

// ChainID retrieves the current chain ID for transaction replay protection.
func (c *Client) ChainID(ctx context.Context) (*big.Int, error) {
	var result hexutil.Big
	err := c.c.CallContext(ctx, &result, "eth_chainId")
	if err != nil {
		return nil, err
	}
	return (*big.Int)(&result), nil
}

// BalanceAt returns the wei balance of the given account.
// The block number can be nil, in which case the balance is taken from the latest known block.
func (c *Client) BalanceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (*big.Int, error) {
	var result hexutil.Big
	err := c.c.CallContext(ctx, &result, "eth_getBalance", account, toBlockNumArg(blockNumber))
	return (*big.Int)(&result), err
}

// CodeAt returns the contract code of the given account.
// The block number can be nil, in which case the code is taken from the latest known block.
func (c *Client) CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error) {
	var result hexutil.Bytes
	err := c.c.CallContext(ctx, &result, "eth_getCode", account, toBlockNumArg(blockNumber))
	return result, err
}

// StorageAt returns the value of key in the contract storage of the given account.
// The block number can be nil, in which case the value is taken from the latest known block.
func (c *Client) StorageAt(ctx context.Context, account common.Address, key common.Hash, blockNumber *big.Int) ([]byte, error) {
	var result hexutil.Bytes
	err := c.c.CallContext(ctx, &result, "eth_getStorageAt", account, key, toBlockNumArg(blockNumber))
	return result, err
}

// FilterLogs executes a filter query.
func (c *Client) FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
	var result []types.Log
	arg, err := toFilterArg(q)
	if err != nil {
		return nil, err
	}
	err = c.c.CallContext(ctx, &result, "eth_getLogs", arg)
	return result, err
}

// toBlockNumArg converts a block number to the appropriate RPC argument.
func toBlockNumArg(number *big.Int) string {
	if number == nil {
		return "latest"
	}
	if number.Sign() >= 0 {
		return hexutil.EncodeBig(number)
	}
	// It's negative - handle special block numbers
	if number.IsInt64() {
		return rpc.BlockNumber(number.Int64()).String()
	}
	return "latest"
}

// toCallArg converts an ethereum.CallMsg to the appropriate RPC argument.
func toCallArg(msg ethereum.CallMsg) interface{} {
	arg := map[string]interface{}{
		"from": msg.From,
		"to":   msg.To,
	}
	if len(msg.Data) > 0 {
		arg["input"] = hexutil.Bytes(msg.Data)
	}
	if msg.Value != nil {
		arg["value"] = (*hexutil.Big)(msg.Value)
	}
	if msg.Gas != 0 {
		arg["gas"] = hexutil.Uint64(msg.Gas)
	}
	// For RSK, we use gasPrice instead of EIP-1559 fields
	if msg.GasPrice != nil {
		arg["gasPrice"] = (*hexutil.Big)(msg.GasPrice)
	} else if msg.GasFeeCap != nil {
		// If EIP-1559 fields are set, use GasFeeCap as gasPrice for RSK compatibility
		arg["gasPrice"] = (*hexutil.Big)(msg.GasFeeCap)
	}
	// Note: We intentionally ignore GasTipCap, BlobGasFeeCap, BlobHashes, and AccessList
	// as RSK doesn't support these EIP-1559/EIP-4844 features
	return arg
}

// toFilterArg converts an ethereum.FilterQuery to the appropriate RPC argument.
func toFilterArg(q ethereum.FilterQuery) (interface{}, error) {
	arg := map[string]interface{}{
		"address": q.Addresses,
		"topics":  q.Topics,
	}
	if q.BlockHash != nil {
		arg["blockHash"] = *q.BlockHash
		if q.FromBlock != nil || q.ToBlock != nil {
			return nil, errors.New("cannot specify both BlockHash and FromBlock/ToBlock")
		}
	} else {
		if q.FromBlock == nil {
			arg["fromBlock"] = "0x0"
		} else {
			arg["fromBlock"] = toBlockNumArg(q.FromBlock)
		}
		arg["toBlock"] = toBlockNumArg(q.ToBlock)
	}
	return arg, nil
}
