package ethclient

import (
	"context"
	"fmt"
	"math/big"
	"time"

	opcrypto "github.com/ethereum-optimism/optimism/op-service/crypto"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-service/txmgr"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
)

// RSKTxMgrConfig provides RSK-specific default configuration values for txmgr.
// These are tuned for RSK's ~30 second block time and legacy gas pricing.
var RSKTxMgrConfig = struct {
	NumConfirmations          uint64
	SafeAbortNonceTooLowCount uint64
	FeeLimitMultiplier        uint64
	FeeLimitThresholdGwei     float64
	MinTipCapGwei             float64
	MinBaseFeeGwei            float64
	RebroadcastInterval       time.Duration
	ResubmissionTimeout       time.Duration
	NetworkTimeout            time.Duration
	RetryInterval             time.Duration
	MaxRetries                uint64
	TxSendTimeout             time.Duration
	TxNotInMempoolTimeout     time.Duration
	ReceiptQueryInterval      time.Duration
}{
	NumConfirmations:          1, // ~1 minute at 30s blocks
	SafeAbortNonceTooLowCount: 3,
	FeeLimitMultiplier:        5,
	FeeLimitThresholdGwei:     1.0,             // RSK has lower fees
	MinTipCapGwei:             0.06,            // RSK minimum gas price is often 0.06 gwei
	MinBaseFeeGwei:            0.06,            // Match minimumGasPrice
	RebroadcastInterval:       1 * time.Second, // RSK block time
	ResubmissionTimeout:       1 * time.Second, // ~1 block
	NetworkTimeout:            10 * time.Second,
	RetryInterval:             1 * time.Second,
	MaxRetries:                10,
	TxSendTimeout:             0, // Unbounded
	TxNotInMempoolTimeout:     3 * time.Minute,
	ReceiptQueryInterval:      1 * time.Second, // RSK block time
}

// NewRSKTxMgrConfig creates a txmgr.Config configured for RSK networks.
// It uses the RSK ethclient and RSKGasPriceEstimatorFn instead of the default
// Ethereum client and estimator.
//
// Parameters:
//   - rpcURL: RSK node RPC endpoint
//   - chainID: RSK chain ID (30 for mainnet, 31 for testnet)
//   - signer: Transaction signing function
//   - from: Sender address
//   - l: Logger
//
// Usage:
//
//	cfg, err := ethclient.NewRSKTxMgrConfig(
//	    "https://public-node.testnet.rsk.co",
//	    big.NewInt(31),
//	    signerFn,
//	    fromAddr,
//	    logger,
//	)
//	if err != nil {
//	    return err
//	}
//	mgr, err := txmgr.NewSimpleTxManager("rsk-txmgr", logger, metrics, cfg)
func NewRSKTxMgrConfig(
	ctx context.Context,
	rpcURL string,
	signer opcrypto.SignerFn,
	from common.Address,
	l log.Logger,
) (*txmgr.Config, error) {
	// Create RSK client
	client, err := DialContext(ctx, rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to RSK node: %w", err)
	}

	// Get chain ID from the node
	chainID, err := client.ChainID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get chain ID: %w", err)
	}

	// Convert gwei values to wei
	feeLimitThreshold, err := eth.GweiToWei(RSKTxMgrConfig.FeeLimitThresholdGwei)
	if err != nil {
		return nil, fmt.Errorf("invalid fee limit threshold: %w", err)
	}

	minBaseFee, err := eth.GweiToWei(RSKTxMgrConfig.MinBaseFeeGwei)
	if err != nil {
		return nil, fmt.Errorf("invalid min base fee: %w", err)
	}

	minTipCap, err := eth.GweiToWei(RSKTxMgrConfig.MinTipCapGwei)
	if err != nil {
		return nil, fmt.Errorf("invalid min tip cap: %w", err)
	}

	// Create the config
	cfg := &txmgr.Config{
		Backend: client,
		ChainID: chainID,
		Signer:  signer,
		From:    from,

		// Use RSK gas price estimator instead of default (which requires blob support)
		GasPriceEstimatorFn: RSKGasPriceEstimatorFn,

		TxSendTimeout:              RSKTxMgrConfig.TxSendTimeout,
		TxNotInMempoolTimeout:      RSKTxMgrConfig.TxNotInMempoolTimeout,
		NetworkTimeout:             RSKTxMgrConfig.NetworkTimeout,
		RetryInterval:              RSKTxMgrConfig.RetryInterval,
		MaxRetries:                 RSKTxMgrConfig.MaxRetries,
		ReceiptQueryInterval:       RSKTxMgrConfig.ReceiptQueryInterval,
		NumConfirmations:           RSKTxMgrConfig.NumConfirmations,
		SafeAbortNonceTooLowCount:  RSKTxMgrConfig.SafeAbortNonceTooLowCount,
		AlreadyPublishedCustomErrs: nil,
		CellProofTime:              1<<63 - 1, // Disabled - RSK doesn't support blobs
	}

	// Set atomic values
	cfg.RebroadcastInterval.Store(int64(RSKTxMgrConfig.RebroadcastInterval))
	cfg.ResubmissionTimeout.Store(int64(RSKTxMgrConfig.ResubmissionTimeout))
	cfg.FeeLimitThreshold.Store(feeLimitThreshold)
	cfg.FeeLimitMultiplier.Store(RSKTxMgrConfig.FeeLimitMultiplier)
	cfg.MinBaseFee.Store(minBaseFee)
	cfg.MinTipCap.Store(minTipCap)
	cfg.MinBlobTxFee.Store(big.NewInt(1)) // Dummy value since RSK doesn't support blobs

	return cfg, nil
}

// RSKDeployerGasPriceEstimator is a custom gas price estimator for use with op-deployer
// on RSK networks. It pads the gas price by 50% to ensure transactions get included.
//
// Unlike the standard DeployerGasPriceEstimator, this one:
//   - Returns zero for blob fees (RSK doesn't support blobs)
//   - Uses gasPrice instead of tip+baseFee model
//
// Note: We return zero instead of nil for blob fees to avoid nil pointer
// dereference in txmgr.SuggestGasPriceCaps which compares blob fees.
//
// Usage:
//
//	cfg := &txmgr.Config{
//	    Backend:             rskClient,
//	    GasPriceEstimatorFn: ethclient.RSKDeployerGasPriceEstimator,
//	    // ... other config
//	}
func RSKDeployerGasPriceEstimator(ctx context.Context, client txmgr.ETHBackend) (*big.Int, *big.Int, *big.Int, error) {
	// Get current gas price from RSK node
	// We use SuggestGasTipCap which maps to eth_gasPrice for RSK clients
	gasPrice, err := client.SuggestGasTipCap(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get gas price: %w", err)
	}

	// Get header for minimumGasPrice (mapped to BaseFee)
	chainHead, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get block: %w", err)
	}

	baseFee := chainHead.BaseFee
	if baseFee == nil {
		// If no minimumGasPrice, use gasPrice
		baseFee = new(big.Int).Set(gasPrice)
	}

	// Pad gas price by 50%
	baseFeePadFactor := big.NewInt(2)
	baseFeePad := new(big.Int).Div(baseFee, baseFeePadFactor)
	paddedBaseFee := new(big.Int).Add(baseFee, baseFeePad)

	// Multiply tip by 5 (capped at 5 gwei for RSK)
	tipMulFactor := big.NewInt(5)
	paddedTip := new(big.Int).Mul(gasPrice, tipMulFactor)

	// RSK-specific caps (lower than Ethereum due to lower fees)
	minTip := big.NewInt(60000000)   // 0.06 gwei - RSK minimum
	maxTip := big.NewInt(5000000000) // 5 gwei

	if paddedTip.Cmp(minTip) < 0 {
		paddedTip.Set(minTip)
	}

	if paddedTip.Cmp(maxTip) > 0 {
		paddedTip.Set(maxTip)
	}

	// Return zero for blob fees (RSK doesn't support blobs)
	// We use zero instead of nil to avoid nil pointer dereference in txmgr
	return paddedTip, paddedBaseFee, big.NewInt(0), nil
}
