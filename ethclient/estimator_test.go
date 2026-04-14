package ethclient

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockETHBackend implements ETHBackend and gasPriceSuggester for testing.
type mockETHBackend struct {
	gasPrice    *big.Int
	gasPriceErr error
	gasTipCap   *big.Int
	gasTipErr   error
	header      *types.Header
	headerErr   error
}

func (m *mockETHBackend) BlockNumber(ctx context.Context) (uint64, error) {
	return 0, nil
}

func (m *mockETHBackend) CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	return nil, nil
}

func (m *mockETHBackend) TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
	return nil, nil
}

func (m *mockETHBackend) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	return nil
}

func (m *mockETHBackend) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	if m.headerErr != nil {
		return nil, m.headerErr
	}
	return m.header, nil
}

func (m *mockETHBackend) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	if m.gasTipErr != nil {
		return nil, m.gasTipErr
	}
	return m.gasTipCap, nil
}

func (m *mockETHBackend) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	if m.gasPriceErr != nil {
		return nil, m.gasPriceErr
	}
	return m.gasPrice, nil
}

func (m *mockETHBackend) BlobBaseFee(ctx context.Context) (*big.Int, error) {
	return nil, ErrBlobsNotSupported
}

func (m *mockETHBackend) NonceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (uint64, error) {
	return 0, nil
}

func (m *mockETHBackend) PendingNonceAt(ctx context.Context, account common.Address) (uint64, error) {
	return 0, nil
}

func (m *mockETHBackend) EstimateGas(ctx context.Context, msg ethereum.CallMsg) (uint64, error) {
	return 21000, nil
}

func (m *mockETHBackend) Close() {}

// mockETHBackendNoGasPrice implements ETHBackend but NOT gasPriceSuggester,
// forcing the estimator to fall back to SuggestGasTipCap.
type mockETHBackendNoGasPrice struct {
	gasTipCap *big.Int
	gasTipErr error
}

func (m *mockETHBackendNoGasPrice) BlockNumber(ctx context.Context) (uint64, error) {
	return 0, nil
}
func (m *mockETHBackendNoGasPrice) CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	return nil, nil
}
func (m *mockETHBackendNoGasPrice) TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
	return nil, nil
}
func (m *mockETHBackendNoGasPrice) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	return nil
}
func (m *mockETHBackendNoGasPrice) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	return &types.Header{}, nil
}
func (m *mockETHBackendNoGasPrice) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	if m.gasTipErr != nil {
		return nil, m.gasTipErr
	}
	return m.gasTipCap, nil
}
func (m *mockETHBackendNoGasPrice) BlobBaseFee(ctx context.Context) (*big.Int, error) {
	return nil, ErrBlobsNotSupported
}
func (m *mockETHBackendNoGasPrice) NonceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (uint64, error) {
	return 0, nil
}
func (m *mockETHBackendNoGasPrice) PendingNonceAt(ctx context.Context, account common.Address) (uint64, error) {
	return 0, nil
}
func (m *mockETHBackendNoGasPrice) EstimateGas(ctx context.Context, msg ethereum.CallMsg) (uint64, error) {
	return 21000, nil
}
func (m *mockETHBackendNoGasPrice) Close() {}

func TestRSKGasPriceEstimatorFn(t *testing.T) {
	tests := []struct {
		name            string
		gasPrice        *big.Int
		expectedTip     *big.Int
		expectedBaseFee *big.Int
	}{
		{
			name:            "normal gas price",
			gasPrice:        big.NewInt(26_000_000),  // ~0.026 gwei (RSK testnet)
			expectedTip:     big.NewInt(26_000_000),  // = gasPrice
			expectedBaseFee: new(big.Int),            // always 0
		},
		{
			name:            "high gas price",
			gasPrice:        big.NewInt(100_000_000_000), // 100 Gwei
			expectedTip:     big.NewInt(100_000_000_000), // = gasPrice
			expectedBaseFee: new(big.Int),                // always 0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &mockETHBackend{
				gasPrice: tt.gasPrice,
			}

			tip, baseFee, blobBaseFee, err := RSKGasPriceEstimatorFn(context.Background(), backend)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedTip, tip, "tip should equal eth_gasPrice")
			assert.Equal(t, tt.expectedBaseFee, baseFee, "baseFee should be zero")
			assert.NotNil(t, blobBaseFee, "blobBaseFee should not be nil")
			assert.Equal(t, int64(0), blobBaseFee.Int64(), "blobBaseFee should be zero for RSK")

			// Verify: gasFeeCap = tip + 2*baseFee = gasPrice (no multiplier)
			gasFeeCap := effectiveLegacyGasPrice(tip, baseFee)
			assert.Equal(t, tt.gasPrice, gasFeeCap, "legacy GasPrice should equal eth_gasPrice exactly")
		})
	}
}

func TestRSKGasPriceEstimatorFn_FallbackToSuggestGasTipCap(t *testing.T) {
	// When the backend does NOT implement gasPriceSuggester,
	// the estimator falls back to SuggestGasTipCap (gorsk's ethclient path).
	backend := &mockETHBackendNoGasPrice{
		gasTipCap: big.NewInt(26_000_000),
	}

	tip, baseFee, blobBaseFee, err := RSKGasPriceEstimatorFn(context.Background(), backend)
	require.NoError(t, err)

	assert.Equal(t, big.NewInt(26_000_000), tip, "tip should equal SuggestGasTipCap result")
	assert.Equal(t, new(big.Int), baseFee, "baseFee should be zero")
	assert.Equal(t, int64(0), blobBaseFee.Int64())
}

func TestRSKGasPriceEstimatorFn_Errors(t *testing.T) {
	t.Run("SuggestGasPrice error", func(t *testing.T) {
		backend := &mockETHBackend{
			gasPriceErr: assert.AnError,
		}

		_, _, _, err := RSKGasPriceEstimatorFn(context.Background(), backend)
		assert.Error(t, err)
	})

	t.Run("SuggestGasTipCap error in fallback path", func(t *testing.T) {
		backend := &mockETHBackendNoGasPrice{
			gasTipErr: assert.AnError,
		}

		_, _, _, err := RSKGasPriceEstimatorFn(context.Background(), backend)
		assert.Error(t, err)
	})
}

func TestRSKGasPriceEstimatorFnWithMinimum(t *testing.T) {
	tests := []struct {
		name            string
		gasPrice        *big.Int
		minGasPrice     *big.Int
		expectedTip     *big.Int
		expectedBaseFee *big.Int
	}{
		{
			name:            "tip above minimum unchanged",
			gasPrice:        big.NewInt(2_000_000_000), // 2 Gwei
			minGasPrice:     big.NewInt(1_000_000_000), // 1 Gwei minimum
			expectedTip:     big.NewInt(2_000_000_000), // unchanged (gasPrice > min)
			expectedBaseFee: new(big.Int),              // always 0
		},
		{
			name:            "tip below minimum gets bumped",
			gasPrice:        big.NewInt(500_000_000),   // 0.5 Gwei
			minGasPrice:     big.NewInt(1_000_000_000), // 1 Gwei minimum
			expectedTip:     big.NewInt(1_000_000_000), // bumped to min
			expectedBaseFee: new(big.Int),              // always 0
		},
		{
			name:            "nil minimum has no effect",
			gasPrice:        big.NewInt(500_000_000), // 0.5 Gwei
			minGasPrice:     nil,
			expectedTip:     big.NewInt(500_000_000), // = gasPrice
			expectedBaseFee: new(big.Int),            // always 0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &mockETHBackend{
				gasPrice: tt.gasPrice,
			}

			estimatorFn := RSKGasPriceEstimatorFnWithMinimum(tt.minGasPrice)
			tip, baseFee, blobBaseFee, err := estimatorFn(context.Background(), backend)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedTip, tip)
			assert.Equal(t, tt.expectedBaseFee, baseFee)
			assert.NotNil(t, blobBaseFee, "blobBaseFee should not be nil")
			assert.Equal(t, int64(0), blobBaseFee.Int64(), "blobBaseFee should be zero for RSK")
		})
	}
}

func TestRSKGasPriceEstimatorFnWithMinimum_Error(t *testing.T) {
	backend := &mockETHBackend{
		gasPriceErr: assert.AnError,
	}

	estimatorFn := RSKGasPriceEstimatorFnWithMinimum(big.NewInt(1_000_000_000))
	_, _, _, err := estimatorFn(context.Background(), backend)
	assert.Error(t, err)
}

// effectiveLegacyGasPrice is txmgr's calcGasFeeCap(tip, baseFee) = tip + 2*baseFee for UseLegacyTx.
func effectiveLegacyGasPrice(tip, baseFee *big.Int) *big.Int {
	two := big.NewInt(2)
	out := new(big.Int).Mul(baseFee, two)
	return out.Add(out, tip)
}

func TestRSKGasPriceEstimatorFnWithMinimumLegacyGasPrice(t *testing.T) {
	minSevenFiveM := big.NewInt(7_500_000)

	tests := []struct {
		name          string
		gasPrice      *big.Int
		minLegacy     *big.Int
		wantTip       *big.Int
		wantBaseFee   *big.Int
		wantMinLegacy *big.Int // minimum required legacy gas price (= tip since baseFee=0)
	}{
		{
			name:          "RPC below floor bumps tip to min",
			gasPrice:      big.NewInt(1_000_000),
			minLegacy:     minSevenFiveM,
			wantTip:       minSevenFiveM,
			wantBaseFee:   new(big.Int),
			wantMinLegacy: minSevenFiveM,
		},
		{
			name:          "RPC at minimum unchanged",
			gasPrice:      new(big.Int).Set(minSevenFiveM),
			minLegacy:     minSevenFiveM,
			wantTip:       minSevenFiveM,
			wantBaseFee:   new(big.Int),
			wantMinLegacy: minSevenFiveM,
		},
		{
			name:          "RPC above floor unchanged",
			gasPrice:      big.NewInt(10_000_000),
			minLegacy:     minSevenFiveM,
			wantTip:       big.NewInt(10_000_000),
			wantBaseFee:   new(big.Int),
			wantMinLegacy: big.NewInt(10_000_000),
		},
		{
			name:          "nil minimum passes through",
			gasPrice:      big.NewInt(2_000_000),
			minLegacy:     nil,
			wantTip:       big.NewInt(2_000_000),
			wantBaseFee:   new(big.Int),
			wantMinLegacy: big.NewInt(2_000_000),
		},
		{
			name:          "non-positive minimum passes through",
			gasPrice:      big.NewInt(2_000_000),
			minLegacy:     big.NewInt(0),
			wantTip:       big.NewInt(2_000_000),
			wantBaseFee:   new(big.Int),
			wantMinLegacy: big.NewInt(2_000_000),
		},
		{
			name:          "small values work correctly",
			gasPrice:      big.NewInt(1),
			minLegacy:     big.NewInt(7),
			wantTip:       big.NewInt(7),
			wantBaseFee:   new(big.Int),
			wantMinLegacy: big.NewInt(7),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &mockETHBackend{gasPrice: tt.gasPrice}
			fn := RSKGasPriceEstimatorFnWithMinimumLegacyGasPrice(tt.minLegacy)
			tip, baseFee, blobBaseFee, err := fn(context.Background(), backend)
			require.NoError(t, err)

			assert.Equal(t, tt.wantTip, tip)
			assert.Equal(t, tt.wantBaseFee, baseFee)
			assert.Equal(t, int64(0), blobBaseFee.Int64())

			// Legacy GasPrice = tip + 2*baseFee = tip (since baseFee=0)
			eff := effectiveLegacyGasPrice(tip, baseFee)
			assert.True(t, eff.Cmp(tt.wantMinLegacy) >= 0,
				"tip+2*baseFee=%s should be >= %s", eff, tt.wantMinLegacy)
		})
	}
}

func TestRSKGasPriceEstimatorFnWithMinimumLegacyGasPrice_FallbackBackend(t *testing.T) {
	backend := &mockETHBackendNoGasPrice{gasTipCap: big.NewInt(1_000_000)}
	fn := RSKGasPriceEstimatorFnWithMinimumLegacyGasPrice(big.NewInt(7_500_000))
	tip, baseFee, _, err := fn(context.Background(), backend)
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(7_500_000), tip)  // bumped from 1M to 7.5M floor
	assert.Equal(t, new(big.Int), baseFee)        // always 0
	assert.Equal(t, big.NewInt(7_500_000), effectiveLegacyGasPrice(tip, baseFee))
}

func TestRSKGasPriceEstimatorFnWithMinimumLegacyGasPrice_Error(t *testing.T) {
	backend := &mockETHBackend{gasPriceErr: assert.AnError}
	fn := RSKGasPriceEstimatorFnWithMinimumLegacyGasPrice(big.NewInt(7_500_000))
	_, _, _, err := fn(context.Background(), backend)
	assert.Error(t, err)
}
