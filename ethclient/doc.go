// Package ethclient provides an RSK-compatible Ethereum client that implements
// the ETHBackend interface from github.com/ethereum-optimism/optimism/op-service/txmgr.
//
// RSK (Rootstock) is a Bitcoin sidechain that supports smart contracts and is
// largely compatible with Ethereum. However, there are several key differences
// that this package handles:
//
// # EIP-1559 (Not Supported)
//
// RSK uses legacy gas pricing (gasPrice) instead of the EIP-1559 model with
// baseFee and priorityFee. This package maps RSK's minimumGasPrice to BaseFee
// for compatibility with code expecting EIP-1559 fields.
//
// # Blob Transactions (Not Supported)
//
// RSK doesn't support EIP-4844 blob transactions. The BlobBaseFee() method
// returns ErrBlobsNotSupported.
//
// # Header Structure
//
// RSK headers contain additional fields for merged mining (bitcoinMergedMining*)
// and minimumGasPrice instead of baseFeePerGas. This package handles the
// conversion to standard go-ethereum types.Header.
//
// # Integration with gorsk
//
// This package is part of the gorsk library, which provides comprehensive RSK
// block verification functionality including:
//   - Block hash computation (rskblocks/)
//   - Binary trie implementation (rsktrie/)
//   - Transaction/receipt root verification
//   - Account proof verification
//
// # Usage with op-service/txmgr
//
// The easiest way to use this package with op-service is via NewRSKTxMgrConfig:
//
//	import (
//	    "gorsk/ethclient"
//	    "github.com/ethereum-optimism/optimism/op-service/txmgr"
//	)
//
//	// Create RSK-configured txmgr config
//	cfg, err := ethclient.NewRSKTxMgrConfig(
//	    ctx,
//	    "https://public-node.testnet.rsk.co",
//	    signerFn,
//	    fromAddr,
//	    logger,
//	)
//	if err != nil {
//	    return err
//	}
//
//	// Create the transaction manager
//	mgr, err := txmgr.NewSimpleTxManager("rsk-txmgr", logger, metrics, cfg)
//
// For manual configuration:
//
//	// Create RSK client
//	client, err := ethclient.Dial("https://public-node.testnet.rsk.co")
//	if err != nil {
//	    return err
//	}
//	defer client.Close()
//
//	// Create txmgr config with RSK backend and custom estimator
//	conf := &txmgr.Config{
//	    Backend:             client,
//	    GasPriceEstimatorFn: ethclient.RSKGasPriceEstimatorFn,
//	    // ... other config
//	}
//
// # Usage with op-deployer
//
// For op-deployer, use RSKDeployerGasPriceEstimator which pads gas prices
// appropriately for contract deployments:
//
//	cfg := &txmgr.Config{
//	    Backend:             rskClient,
//	    GasPriceEstimatorFn: ethclient.RSKDeployerGasPriceEstimator,
//	    // ... other config
//	}
//
// # Gas Price Estimators
//
// This package provides three gas price estimator functions:
//
//   - RSKGasPriceEstimatorFn: Basic estimator that uses eth_gasPrice and
//     minimumGasPrice from the header. Returns nil for blob fees.
//
//   - RSKGasPriceEstimatorFnWithMinimum: Wrapper that enforces minimum gas
//     prices for networks with very low fees.
//
//   - RSKDeployerGasPriceEstimator: Pads gas prices by 50% and multiplies
//     tip by 5x (capped at 5 gwei) for reliable contract deployments.
//
// # RSK Networks
//
// Common RSK RPC endpoints:
//   - RSK Mainnet: https://public-node.rsk.co
//   - RSK Testnet: https://public-node.testnet.rsk.co
//
// Chain IDs:
//   - RSK Mainnet: 30
//   - RSK Testnet: 31
package ethclient
