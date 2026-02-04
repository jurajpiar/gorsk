package ethclient

import (
	"context"
	"math/big"

	"github.com/ethereum-optimism/optimism/op-service/txmgr"
)

// RSKGasPriceEstimatorFn is a GasPriceEstimatorFn for RSK that handles the lack of EIP-1559.
//
// Since RSK doesn't support EIP-1559:
//   - tip (gasTipCap) is set to the result of eth_gasPrice
//   - baseFee is set to minimumGasPrice from the header (or gasPrice as fallback)
//   - blobTipCap and blobBaseFee are zero (RSK doesn't support blobs)
//
// Note: We return zero instead of nil for blob fees to avoid nil pointer
// dereference in txmgr.SuggestGasPriceCaps which compares blob fees.
//
// This function is compatible with txmgr.GasPriceEstimatorFn and can be passed
// to txmgr.Config.GasPriceEstimatorFn when using Client as the backend.
//
// Usage:
//
//	conf := &txmgr.Config{
//	    Backend:             rskBackend,
//	    GasPriceEstimatorFn: ethclient.RSKGasPriceEstimatorFn,
//	    // ... other config
//	}
func RSKGasPriceEstimatorFn(ctx context.Context, backend txmgr.ETHBackend) (*big.Int, *big.Int, *big.Int, error) {
	// Get the current gas price from the network
	// In RSK, eth_gasPrice returns the suggested gas price for transactions
	// We use SuggestGasTipCap which maps to eth_gasPrice for RSK clients
	gasPrice, err := backend.SuggestGasTipCap(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	// Get the header to extract minimumGasPrice (mapped to BaseFee)
	head, err := backend.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, nil, nil, err
	}

	// Use minimumGasPrice (stored in BaseFee) as the base fee
	// If not available, fall back to gasPrice
	baseFee := head.BaseFee
	if baseFee == nil {
		baseFee = new(big.Int).Set(gasPrice)
	}

	// For RSK:
	// - tip = gasPrice (since there's no separate priority fee concept)
	// - baseFee = minimumGasPrice from header
	// - blobTipCap = 0 (no blob support, but non-nil to avoid panic in txmgr)
	// - blobBaseFee = 0 (no blob support, but non-nil to avoid panic in txmgr)
	return gasPrice, baseFee, big.NewInt(0), nil
}

// RSKGasPriceEstimatorFnWithMinimum returns a GasPriceEstimatorFn that enforces
// minimum gas price values. This is useful for ensuring transactions have
// sufficient gas prices on RSK networks.
//
// Parameters:
//   - minGasPrice: Minimum gas price to return (can be nil to skip enforcement)
//
// Usage:
//
//	minGasPrice := big.NewInt(1000000000) // 1 Gwei
//	conf := &txmgr.Config{
//	    Backend:             rskBackend,
//	    GasPriceEstimatorFn: ethclient.RSKGasPriceEstimatorFnWithMinimum(minGasPrice),
//	    // ... other config
//	}
func RSKGasPriceEstimatorFnWithMinimum(minGasPrice *big.Int) txmgr.GasPriceEstimatorFn {
	return func(ctx context.Context, backend txmgr.ETHBackend) (*big.Int, *big.Int, *big.Int, error) {
		tip, baseFee, blobTip, err := RSKGasPriceEstimatorFn(ctx, backend)
		if err != nil {
			return nil, nil, nil, err
		}

		// Enforce minimum gas price if specified
		if minGasPrice != nil {
			if tip.Cmp(minGasPrice) < 0 {
				tip = new(big.Int).Set(minGasPrice)
			}
			if baseFee.Cmp(minGasPrice) < 0 {
				baseFee = new(big.Int).Set(minGasPrice)
			}
		}

		return tip, baseFee, blobTip, nil
	}
}
