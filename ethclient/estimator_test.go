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

// mockETHBackend implements ETHBackend for testing the estimator functions.
type mockETHBackend struct {
	gasTipCap *big.Int
	gasTipErr error
	header    *types.Header
	headerErr error
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
	if m.gasTipErr != nil {
		return nil, m.gasTipErr
	}
	return m.gasTipCap, nil
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

func TestRSKGasPriceEstimatorFn(t *testing.T) {
	tests := []struct {
		name            string
		gasTipCap       *big.Int
		headerBaseFee   *big.Int
		expectedTip     *big.Int
		expectedBaseFee *big.Int
	}{
		{
			name:            "normal case with minimumGasPrice",
			gasTipCap:       big.NewInt(1000000000), // 1 Gwei
			headerBaseFee:   big.NewInt(500000000),  // 0.5 Gwei (minimumGasPrice)
			expectedTip:     big.NewInt(1000000000),
			expectedBaseFee: big.NewInt(500000000),
		},
		{
			name:            "nil baseFee falls back to gasPrice",
			gasTipCap:       big.NewInt(2000000000), // 2 Gwei
			headerBaseFee:   nil,
			expectedTip:     big.NewInt(2000000000),
			expectedBaseFee: big.NewInt(2000000000), // Falls back to gasPrice
		},
		{
			name:            "high gas price",
			gasTipCap:       big.NewInt(100000000000), // 100 Gwei
			headerBaseFee:   big.NewInt(50000000000),  // 50 Gwei
			expectedTip:     big.NewInt(100000000000),
			expectedBaseFee: big.NewInt(50000000000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &mockETHBackend{
				gasTipCap: tt.gasTipCap,
				header: &types.Header{
					BaseFee: tt.headerBaseFee,
				},
			}

			tip, baseFee, blobBaseFee, err := RSKGasPriceEstimatorFn(context.Background(), backend)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedTip, tip)
			assert.Equal(t, tt.expectedBaseFee, baseFee)
			// Blob fees should be zero (not nil) for RSK to avoid nil pointer dereference in txmgr
			assert.NotNil(t, blobBaseFee, "blobBaseFee should not be nil")
			assert.Equal(t, int64(0), blobBaseFee.Int64(), "blobBaseFee should be zero for RSK")
		})
	}
}

func TestRSKGasPriceEstimatorFn_Errors(t *testing.T) {
	t.Run("SuggestGasTipCap error", func(t *testing.T) {
		backend := &mockETHBackend{
			gasTipErr: assert.AnError,
		}

		_, _, _, err := RSKGasPriceEstimatorFn(context.Background(), backend)
		assert.Error(t, err)
	})

	t.Run("HeaderByNumber error", func(t *testing.T) {
		backend := &mockETHBackend{
			gasTipCap: big.NewInt(1000000000),
			headerErr: assert.AnError,
		}

		_, _, _, err := RSKGasPriceEstimatorFn(context.Background(), backend)
		assert.Error(t, err)
	})
}

func TestRSKGasPriceEstimatorFnWithMinimum(t *testing.T) {
	tests := []struct {
		name            string
		gasTipCap       *big.Int
		headerBaseFee   *big.Int
		minGasPrice     *big.Int
		expectedTip     *big.Int
		expectedBaseFee *big.Int
	}{
		{
			name:            "values above minimum unchanged",
			gasTipCap:       big.NewInt(2000000000), // 2 Gwei
			headerBaseFee:   big.NewInt(1500000000), // 1.5 Gwei
			minGasPrice:     big.NewInt(1000000000), // 1 Gwei minimum
			expectedTip:     big.NewInt(2000000000),
			expectedBaseFee: big.NewInt(1500000000),
		},
		{
			name:            "tip below minimum gets bumped",
			gasTipCap:       big.NewInt(500000000),  // 0.5 Gwei
			headerBaseFee:   big.NewInt(1500000000), // 1.5 Gwei
			minGasPrice:     big.NewInt(1000000000), // 1 Gwei minimum
			expectedTip:     big.NewInt(1000000000), // Bumped to minimum
			expectedBaseFee: big.NewInt(1500000000),
		},
		{
			name:            "baseFee below minimum gets bumped",
			gasTipCap:       big.NewInt(2000000000), // 2 Gwei
			headerBaseFee:   big.NewInt(500000000),  // 0.5 Gwei
			minGasPrice:     big.NewInt(1000000000), // 1 Gwei minimum
			expectedTip:     big.NewInt(2000000000),
			expectedBaseFee: big.NewInt(1000000000), // Bumped to minimum
		},
		{
			name:            "both below minimum get bumped",
			gasTipCap:       big.NewInt(100000000),  // 0.1 Gwei
			headerBaseFee:   big.NewInt(200000000),  // 0.2 Gwei
			minGasPrice:     big.NewInt(1000000000), // 1 Gwei minimum
			expectedTip:     big.NewInt(1000000000), // Bumped to minimum
			expectedBaseFee: big.NewInt(1000000000), // Bumped to minimum
		},
		{
			name:            "nil minimum has no effect",
			gasTipCap:       big.NewInt(500000000), // 0.5 Gwei
			headerBaseFee:   big.NewInt(200000000), // 0.2 Gwei
			minGasPrice:     nil,
			expectedTip:     big.NewInt(500000000),
			expectedBaseFee: big.NewInt(200000000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &mockETHBackend{
				gasTipCap: tt.gasTipCap,
				header: &types.Header{
					BaseFee: tt.headerBaseFee,
				},
			}

			estimatorFn := RSKGasPriceEstimatorFnWithMinimum(tt.minGasPrice)
			tip, baseFee, blobBaseFee, err := estimatorFn(context.Background(), backend)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedTip, tip)
			assert.Equal(t, tt.expectedBaseFee, baseFee)
			// Blob fees should be zero (not nil) for RSK to avoid nil pointer dereference in txmgr
			assert.NotNil(t, blobBaseFee, "blobBaseFee should not be nil")
			assert.Equal(t, int64(0), blobBaseFee.Int64(), "blobBaseFee should be zero for RSK")
		})
	}
}

func TestRSKGasPriceEstimatorFnWithMinimum_Error(t *testing.T) {
	backend := &mockETHBackend{
		gasTipErr: assert.AnError,
	}

	estimatorFn := RSKGasPriceEstimatorFnWithMinimum(big.NewInt(1000000000))
	_, _, _, err := estimatorFn(context.Background(), backend)
	assert.Error(t, err)
}
