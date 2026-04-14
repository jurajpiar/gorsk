package ethclient

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRPCServer creates a test HTTP server that responds to JSON-RPC requests.
func mockRPCServer(t *testing.T, handler func(method string, params []json.RawMessage) (interface{}, error)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID      json.RawMessage   `json:"id"`
			Method  string            `json:"method"`
			Params  []json.RawMessage `json:"params"`
			JSONRPC string            `json:"jsonrpc"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("failed to decode request: %v", err)
		}

		result, err := handler(req.Method, req.Params)

		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      req.ID,
		}
		if err != nil {
			resp["error"] = map[string]interface{}{
				"code":    -32000,
				"message": err.Error(),
			}
		} else {
			resp["result"] = result
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
}

func TestBlockNumber(t *testing.T) {
	server := mockRPCServer(t, func(method string, params []json.RawMessage) (interface{}, error) {
		assert.Equal(t, "eth_blockNumber", method)
		return "0x1234", nil
	})
	defer server.Close()

	client, err := Dial(server.URL)
	require.NoError(t, err)
	defer client.Close()

	blockNum, err := client.BlockNumber(context.Background())
	require.NoError(t, err)
	assert.Equal(t, uint64(0x1234), blockNum)
}

func TestChainID(t *testing.T) {
	server := mockRPCServer(t, func(method string, params []json.RawMessage) (interface{}, error) {
		assert.Equal(t, "eth_chainId", method)
		return "0x1f", nil // 31 = RSK testnet
	})
	defer server.Close()

	client, err := Dial(server.URL)
	require.NoError(t, err)
	defer client.Close()

	chainID, err := client.ChainID(context.Background())
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(31), chainID)
}

func TestSuggestGasTipCap(t *testing.T) {
	server := mockRPCServer(t, func(method string, params []json.RawMessage) (interface{}, error) {
		assert.Equal(t, "eth_gasPrice", method)
		return "0x3b9aca00", nil // 1 Gwei
	})
	defer server.Close()

	client, err := Dial(server.URL)
	require.NoError(t, err)
	defer client.Close()

	tipCap, err := client.SuggestGasTipCap(context.Background())
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(1000000000), tipCap)
}

func TestSuggestGasPrice(t *testing.T) {
	server := mockRPCServer(t, func(method string, params []json.RawMessage) (interface{}, error) {
		assert.Equal(t, "eth_gasPrice", method)
		return "0x77359400", nil // 2 Gwei
	})
	defer server.Close()

	client, err := Dial(server.URL)
	require.NoError(t, err)
	defer client.Close()

	gasPrice, err := client.SuggestGasPrice(context.Background())
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(2000000000), gasPrice)
}

func TestBlobBaseFee_ReturnsError(t *testing.T) {
	// BlobBaseFee should always return an error for RSK
	client := &Client{c: nil}
	_, err := client.BlobBaseFee(context.Background())
	assert.ErrorIs(t, err, ErrBlobsNotSupported)
}

func TestNonceAt(t *testing.T) {
	expectedAddr := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")

	server := mockRPCServer(t, func(method string, params []json.RawMessage) (interface{}, error) {
		assert.Equal(t, "eth_getTransactionCount", method)
		assert.Len(t, params, 2)

		var addr string
		json.Unmarshal(params[0], &addr)
		assert.Equal(t, expectedAddr.Hex(), common.HexToAddress(addr).Hex())

		return "0xa", nil // nonce = 10
	})
	defer server.Close()

	client, err := Dial(server.URL)
	require.NoError(t, err)
	defer client.Close()

	nonce, err := client.NonceAt(context.Background(), expectedAddr, nil)
	require.NoError(t, err)
	assert.Equal(t, uint64(10), nonce)
}

func TestPendingNonceAt(t *testing.T) {
	expectedAddr := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")

	server := mockRPCServer(t, func(method string, params []json.RawMessage) (interface{}, error) {
		assert.Equal(t, "eth_getTransactionCount", method)
		assert.Len(t, params, 2)

		var blockTag string
		json.Unmarshal(params[1], &blockTag)
		assert.Equal(t, "pending", blockTag)

		return "0xb", nil // nonce = 11
	})
	defer server.Close()

	client, err := Dial(server.URL)
	require.NoError(t, err)
	defer client.Close()

	nonce, err := client.PendingNonceAt(context.Background(), expectedAddr)
	require.NoError(t, err)
	assert.Equal(t, uint64(11), nonce)
}

func TestEstimateGas(t *testing.T) {
	server := mockRPCServer(t, func(method string, params []json.RawMessage) (interface{}, error) {
		assert.Equal(t, "eth_estimateGas", method)
		return "0x5208", nil // 21000 gas
	})
	defer server.Close()

	client, err := Dial(server.URL)
	require.NoError(t, err)
	defer client.Close()

	to := common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12")
	gas, err := client.EstimateGas(context.Background(), ethereum.CallMsg{
		To:    &to,
		Value: big.NewInt(1000000000000000000), // 1 ETH
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(21000), gas)
}

func TestHeaderByNumber(t *testing.T) {
	// Create a valid 512-byte logsBloom as hex (256 bytes = 512 hex chars)
	logsBloom := "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

	server := mockRPCServer(t, func(method string, params []json.RawMessage) (interface{}, error) {
		assert.Equal(t, "eth_getBlockByNumber", method)
		return map[string]interface{}{
			"parentHash":       "0x0000000000000000000000000000000000000000000000000000000000000000",
			"sha3Uncles":       "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
			"miner":            "0x0000000000000000000000000000000000000000",
			"stateRoot":        "0x0000000000000000000000000000000000000000000000000000000000000000",
			"transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
			"receiptsRoot":     "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
			"logsBloom":        logsBloom,
			"difficulty":       "0x1",
			"number":           "0x100",
			"gasLimit":         "0x1c9c380",
			"gasUsed":          "0x5208",
			"timestamp":        "0x5f5e100",
			"extraData":        "0x",
			"mixHash":          "0x0000000000000000000000000000000000000000000000000000000000000000",
			"nonce":            "0x0000000000000000",
			"minimumGasPrice":  "0x3b9aca00", // 1 Gwei - RSK specific field
			"hash":             "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		}, nil
	})
	defer server.Close()

	client, err := Dial(server.URL)
	require.NoError(t, err)
	defer client.Close()

	header, err := client.HeaderByNumber(context.Background(), big.NewInt(256))
	require.NoError(t, err)

	assert.Equal(t, big.NewInt(256), header.Number)
	assert.Equal(t, uint64(21000), header.GasUsed)
	// Verify minimumGasPrice is mapped to BaseFee
	assert.Equal(t, big.NewInt(1000000000), header.BaseFee)
}

func TestHeaderByNumber_NotFound(t *testing.T) {
	server := mockRPCServer(t, func(method string, params []json.RawMessage) (interface{}, error) {
		return nil, nil // Return null for not found
	})
	defer server.Close()

	client, err := Dial(server.URL)
	require.NoError(t, err)
	defer client.Close()

	_, err = client.HeaderByNumber(context.Background(), big.NewInt(999999999))
	assert.ErrorIs(t, err, ethereum.NotFound)
}

func TestCallContract(t *testing.T) {
	server := mockRPCServer(t, func(method string, params []json.RawMessage) (interface{}, error) {
		assert.Equal(t, "eth_call", method)
		return "0x0000000000000000000000000000000000000000000000000000000000000001", nil
	})
	defer server.Close()

	client, err := Dial(server.URL)
	require.NoError(t, err)
	defer client.Close()

	to := common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12")
	result, err := client.CallContract(context.Background(), ethereum.CallMsg{
		To:   &to,
		Data: []byte{0x01, 0x02, 0x03},
	}, nil)
	require.NoError(t, err)
	assert.Len(t, result, 32)
}

func TestBalanceAt(t *testing.T) {
	server := mockRPCServer(t, func(method string, params []json.RawMessage) (interface{}, error) {
		assert.Equal(t, "eth_getBalance", method)
		return "0xde0b6b3a7640000", nil // 1 ETH in wei
	})
	defer server.Close()

	client, err := Dial(server.URL)
	require.NoError(t, err)
	defer client.Close()

	addr := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	balance, err := client.BalanceAt(context.Background(), addr, nil)
	require.NoError(t, err)

	oneEth := new(big.Int)
	oneEth.SetString("1000000000000000000", 10)
	assert.Equal(t, oneEth, balance)
}

func TestToBlockNumArg(t *testing.T) {
	tests := []struct {
		name     string
		number   *big.Int
		expected string
	}{
		{"nil returns latest", nil, "latest"},
		{"zero", big.NewInt(0), "0x0"},
		{"positive", big.NewInt(100), "0x64"},
		{"large number", big.NewInt(1000000), "0xf4240"},
		// Note: go-ethereum's rpc.BlockNumber constants:
		// PendingBlockNumber = -1 -> "pending"
		// LatestBlockNumber = -2 -> "latest"
		// FinalizedBlockNumber = -3 -> "finalized"
		// SafeBlockNumber = -4 -> "safe"
		{"negative -1 (pending in rpc.BlockNumber)", big.NewInt(-1), "pending"},
		{"negative -2 (latest in rpc.BlockNumber)", big.NewInt(-2), "latest"},
		{"negative finalized", big.NewInt(-3), "finalized"},
		{"negative safe", big.NewInt(-4), "safe"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toBlockNumArg(tt.number)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestToCallArg(t *testing.T) {
	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")

	msg := ethereum.CallMsg{
		From:     from,
		To:       &to,
		Gas:      21000,
		GasPrice: big.NewInt(1000000000),
		Value:    big.NewInt(1000000000000000000),
		Data:     []byte{0x01, 0x02, 0x03},
	}

	result := toCallArg(msg).(map[string]interface{})

	assert.Equal(t, from, result["from"])
	assert.Equal(t, &to, result["to"])
	assert.NotNil(t, result["gas"])
	assert.NotNil(t, result["gasPrice"])
	assert.NotNil(t, result["value"])
	assert.NotNil(t, result["input"])
}

func TestToCallArg_EIP1559Fallback(t *testing.T) {
	// When GasFeeCap is set (EIP-1559 style), it should be used as gasPrice for RSK
	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")

	msg := ethereum.CallMsg{
		From:      from,
		To:        &to,
		Gas:       21000,
		GasFeeCap: big.NewInt(2000000000), // EIP-1559 field
		GasTipCap: big.NewInt(1000000000), // EIP-1559 field (should be ignored)
	}

	result := toCallArg(msg).(map[string]interface{})

	// GasFeeCap should be used as gasPrice
	assert.NotNil(t, result["gasPrice"])
	// GasTipCap should be ignored (not present in result)
}

func TestNewClient(t *testing.T) {
	// Create a mock RPC client
	server := mockRPCServer(t, func(method string, params []json.RawMessage) (interface{}, error) {
		return "0x1", nil
	})
	defer server.Close()

	rpcClient, err := rpc.Dial(server.URL)
	require.NoError(t, err)

	client := NewClient(rpcClient)
	assert.NotNil(t, client)
	assert.Equal(t, rpcClient, client.Client())

	client.Close()
}

func TestDial(t *testing.T) {
	server := mockRPCServer(t, func(method string, params []json.RawMessage) (interface{}, error) {
		return "0x1", nil
	})
	defer server.Close()

	client, err := Dial(server.URL)
	require.NoError(t, err)
	assert.NotNil(t, client)
	client.Close()
}

func TestDialContext(t *testing.T) {
	server := mockRPCServer(t, func(method string, params []json.RawMessage) (interface{}, error) {
		return "0x1", nil
	})
	defer server.Close()

	client, err := DialContext(context.Background(), server.URL)
	require.NoError(t, err)
	assert.NotNil(t, client)
	client.Close()
}
