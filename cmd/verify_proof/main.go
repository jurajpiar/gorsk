// Command verify_proof fetches and verifies RSK account/storage proofs.
//
// Usage:
//
//	go run ./cmd/verify_proof/ <address> [storage_keys] [block_ref]
//
// Examples:
//
//	# Verify EOA account proof
//	go run ./cmd/verify_proof/ 0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826
//
//	# Verify contract with storage slot 0
//	go run ./cmd/verify_proof/ 0x77045E71a7A2c50903d88e564cD72fab11e82051 0x0
//
//	# Verify multiple storage slots
//	go run ./cmd/verify_proof/ 0x77045E71a7A2c50903d88e564cD72fab11e82051 0x0,0x1,0x2
//
//	# Specify block reference
//	go run ./cmd/verify_proof/ 0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826 "" 0x1234
//
// Flags:
//
//	--rpc-url    RPC endpoint URL (default: http://localhost:4444)
//	--no-verify  Skip proof verification, just fetch and display
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"gorsk/ethclient"
	"gorsk/rskblocks"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

func main() {
	// Parse flags
	rpcURL := flag.String("rpc-url", "http://localhost:4444", "RSKj RPC endpoint URL")
	noVerify := flag.Bool("no-verify", false, "Skip proof verification")
	rawJSON := flag.Bool("json", false, "Output raw JSON response")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: verify_proof [flags] <address> [storage_keys] [block_ref]")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nExamples:")
		fmt.Fprintln(os.Stderr, "  verify_proof 0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826")
		fmt.Fprintln(os.Stderr, "  verify_proof 0x77045E71a7A2c50903d88e564cD72fab11e82051 0x0")
		fmt.Fprintln(os.Stderr, "  verify_proof 0x77045E71a7A2c50903d88e564cD72fab11e82051 0x0,0x1 latest")
		os.Exit(1)
	}

	// Parse address
	address := common.HexToAddress(args[0])

	// Parse storage keys (comma-separated)
	var storageKeys []common.Hash
	if len(args) > 1 && args[1] != "" {
		for _, key := range strings.Split(args[1], ",") {
			storageKeys = append(storageKeys, common.HexToHash(strings.TrimSpace(key)))
		}
	}

	// Parse block reference
	blockRef := "latest"
	if len(args) > 2 {
		blockRef = args[2]
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Connect to RPC
	fmt.Printf("Connecting to %s...\n", *rpcURL)
	client, err := rskblocks.NewProofClient(*rpcURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	// Fetch the proof
	fmt.Printf("Fetching proof for %s at block %s...\n", address.Hex(), blockRef)
	proof, err := client.GetProof(ctx, address, storageKeys, blockRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to fetch proof: %v\n", err)
		os.Exit(1)
	}

	// Output raw JSON if requested
	if *rawJSON {
		data, _ := json.MarshalIndent(proof, "", "  ")
		fmt.Println(string(data))
		return
	}

	// Display proof information
	fmt.Println("\n=== Account Info ===")
	fmt.Printf("Address:      %s\n", proof.Address.Hex())
	fmt.Printf("Balance:      %s wei\n", proof.GetBalance().String())
	fmt.Printf("Nonce:        %d\n", proof.GetNonce())
	fmt.Printf("CodeHash:     %s\n", proof.CodeHash.Hex())
	fmt.Printf("StorageHash:  %s\n", proof.StorageHash.Hex())
	fmt.Printf("Is Contract:  %v\n", proof.IsContract())
	fmt.Printf("Account Proof Nodes: %d\n", len(proof.AccountProof))

	// Display storage proofs
	if len(proof.StorageProof) > 0 {
		fmt.Println("\n=== Storage Proofs ===")
		for _, sp := range proof.StorageProof {
			fmt.Printf("  Key:    %s\n", sp.Key)
			fmt.Printf("  Value:  %s\n", sp.Value)
			fmt.Printf("  Nodes:  %d\n", len(sp.Proofs))
			fmt.Println()
		}
	}

	// Skip verification if requested
	if *noVerify {
		fmt.Println("\nVerification skipped (--no-verify)")
		return
	}

	// Get state root from block header for verification
	fmt.Println("\n=== Verification ===")
	stateRoot, err := getStateRoot(ctx, *rpcURL, blockRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get state root: %v\n", err)
		fmt.Println("Cannot verify proof without state root")
		return
	}
	fmt.Printf("State Root: %s\n", stateRoot.Hex())

	// Verify account proof
	accountProofNodes, err := rskblocks.DecodeRLPProofNodes(proof.AccountProof)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decode account proof: %v\n", err)
		os.Exit(1)
	}

	verifier := rskblocks.NewProofVerifier()
	accountResult, err := verifier.VerifyAccountProof(stateRoot, address, accountProofNodes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Account proof verification error: %v\n", err)
		os.Exit(1)
	}

	if accountResult.Valid {
		fmt.Println("\nAccount Proof: VALID")
		if len(accountResult.Value) > 0 {
			fmt.Printf("  Value (RLP): %s\n", hexutil.Encode(accountResult.Value))
		}
	} else {
		fmt.Println("\nAccount Proof: INVALID")
		if accountResult.Error != nil {
			fmt.Printf("  Error: %v\n", accountResult.Error)
		}
	}

	// Verify storage proofs
	allValid := accountResult.Valid
	for _, sp := range proof.StorageProof {
		keyHash := common.HexToHash(sp.Key)
		proofNodes, err := rskblocks.DecodeRLPProofNodes(sp.Proofs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to decode storage proof for %s: %v\n", sp.Key, err)
			continue
		}

		storageResult, err := verifier.VerifyStorageProof(stateRoot, address, keyHash, proofNodes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Storage proof verification error for %s: %v\n", sp.Key, err)
			continue
		}

		if storageResult.Valid {
			fmt.Printf("\nStorage Proof [%s]: VALID\n", sp.Key)
			if len(storageResult.Value) > 0 {
				fmt.Printf("  Value: %s\n", hexutil.Encode(storageResult.Value))
			}
		} else {
			fmt.Printf("\nStorage Proof [%s]: INVALID\n", sp.Key)
			if storageResult.Error != nil {
				fmt.Printf("  Error: %v\n", storageResult.Error)
			}
			allValid = false
		}
	}

	// Final summary
	fmt.Println("\n=== Summary ===")
	if allValid {
		fmt.Println("All proofs verified successfully!")
	} else {
		fmt.Println("Some proofs failed verification")
		os.Exit(1)
	}
}

// getStateRoot fetches the state root from a block header using the RSK ethclient
func getStateRoot(ctx context.Context, rpcURL, blockRef string) (common.Hash, error) {
	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return common.Hash{}, fmt.Errorf("dial: %w", err)
	}
	defer client.Close()

	// Convert block reference to *big.Int
	var blockNum *big.Int
	switch blockRef {
	case "latest", "":
		blockNum = nil // nil means latest
	case "pending":
		blockNum = big.NewInt(-1)
	case "earliest":
		blockNum = big.NewInt(0)
	default:
		// Parse hex block number
		blockNum = new(big.Int)
		if strings.HasPrefix(blockRef, "0x") {
			blockNum.SetString(blockRef[2:], 16)
		} else {
			blockNum.SetString(blockRef, 10)
		}
	}

	header, err := client.HeaderByNumber(ctx, blockNum)
	if err != nil {
		return common.Hash{}, fmt.Errorf("HeaderByNumber: %w", err)
	}

	return header.Root, nil
}
