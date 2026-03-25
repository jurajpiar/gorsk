package ethclient

import (
	"context"
	"math/big"

	"github.com/ethereum-optimism/optimism/op-service/txmgr"
)

// gasPriceSuggester is an optional interface that backends may implement to
// provide legacy (pre-EIP-1559) gas price estimation via eth_gasPrice.
// go-ethereum's ethclient.Client implements this. This allows the estimator
// to work with any Ethereum client, not just gorsk's RSK-adapted ethclient.
type gasPriceSuggester interface {
	SuggestGasPrice(ctx context.Context) (*big.Int, error)
}

// RSKGasPriceEstimatorFn is a GasPriceEstimatorFn for RSK that handles the
// lack of EIP-1559 and EIP-4844 on the RSK network.
//
// It obtains the gas price via eth_gasPrice (SuggestGasPrice), which works with
// any Ethereum client backend — including go-ethereum's standard ethclient
// connecting directly to an RSK node. This avoids relying on SuggestGasTipCap
// (eth_maxPriorityFeePerGas) which RSK does not support.
//
// Returns:
//   - tip = eth_gasPrice result (used as the effective gas price)
//   - baseFee = 0
//   - blobBaseFee = 0 (RSK doesn't support EIP-4844)
//
// The txmgr computes gasFeeCap = tip + 2*baseFee = gasPrice + 0 = gasPrice.
// For legacy txs (UseLegacyTx), GasPrice = gasFeeCap = eth_gasPrice exactly,
// with no multiplier. RSK's gas price changes slowly compared to Ethereum's
// EIP-1559 baseFee, so the 2x headroom is unnecessary.
//
// Fee bumping works correctly: the txmgr bumps tip by ≥10% on each
// resubmission, which increases the legacy GasPrice accordingly.
//
// Usage:
//
//	conf := &txmgr.Config{
//	    Backend:             anyL1Backend,
//	    GasPriceEstimatorFn: ethclient.RSKGasPriceEstimatorFn,
//	    // ... other config
//	}
func RSKGasPriceEstimatorFn(ctx context.Context, backend txmgr.ETHBackend) (*big.Int, *big.Int, *big.Int, error) {
	// Use eth_gasPrice which every Ethereum client supports and which RSK
	// nodes return the correct suggested gas price from.
	gps, ok := backend.(gasPriceSuggester)
	if !ok {
		// Fallback for backends that only expose SuggestGasTipCap (e.g.
		// gorsk's ethclient where SuggestGasTipCap is mapped to eth_gasPrice).
		gasPrice, err := backend.SuggestGasTipCap(ctx)
		if err != nil {
			return nil, nil, nil, err
		}
		return gasPrice, new(big.Int), big.NewInt(0), nil
	}

	gasPrice, err := gps.SuggestGasPrice(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	// tip=gasPrice, baseFee=0 → gasFeeCap = gasPrice + 2*0 = gasPrice (no multiplier).
	// blobBaseFee=0 because RSK doesn't support EIP-4844.
	return gasPrice, new(big.Int), big.NewInt(0), nil
}

// RSKGasPriceEstimatorFnWithMinimum returns a GasPriceEstimatorFn that enforces
// a minimum gas price. Since RSKGasPriceEstimatorFn returns tip=gasPrice and
// baseFee=0, the effective legacy gas price equals tip. This wrapper ensures
// tip >= minGasPrice.
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

		// Enforce minimum gas price on tip (which is the effective gas price)
		if minGasPrice != nil && tip.Cmp(minGasPrice) < 0 {
			tip = new(big.Int).Set(minGasPrice)
		}

		return tip, baseFee, blobTip, nil
	}
}

// RSKGasPriceEstimatorFnWithMinimumLegacyGasPrice returns a GasPriceEstimatorFn
// that floors the effective legacy gas price used by op-service/txmgr when
// UseLegacyTx is set.
//
// Since RSKGasPriceEstimatorFn returns tip=gasPrice and baseFee=0, the legacy
// GasPrice = gasFeeCap = tip + 2*0 = tip. This wrapper ensures tip >= minLegacyWei.
//
// Pass nil or non-positive minLegacyWei to disable the floor (same as
// RSKGasPriceEstimatorFn alone).
func RSKGasPriceEstimatorFnWithMinimumLegacyGasPrice(minLegacyWei *big.Int) txmgr.GasPriceEstimatorFn {
	return func(ctx context.Context, backend txmgr.ETHBackend) (*big.Int, *big.Int, *big.Int, error) {
		tip, baseFee, blobTip, err := RSKGasPriceEstimatorFn(ctx, backend)
		if err != nil {
			return nil, nil, nil, err
		}
		if minLegacyWei == nil || minLegacyWei.Sign() <= 0 {
			return tip, baseFee, blobTip, nil
		}
		if tip.Cmp(minLegacyWei) < 0 {
			tip = new(big.Int).Set(minLegacyWei)
		}
		return tip, baseFee, blobTip, nil
	}
}
