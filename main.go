// Copyright © 2024 Weald Technology Trading.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/wealdtech/proved/services/chain"
	"github.com/wealdtech/proved/services/generator"
	"github.com/wealdtech/proved/services/verifier"
)

func main() {
	ctx := context.Background()

	chainSvc, err := chain.New(ctx, "http://mainnet-consensus.attestant.io")
	if err != nil {
		panic(err)
	}

	generatorSvc, err := generator.New(ctx, chainSvc)
	if err != nil {
		panic(err)
	}

	verifierSvc, err := verifier.New(ctx, chainSvc)
	if err != nil {
		panic(err)
	}

	state, err := chainSvc.State(ctx, os.Args[1])
	if err != nil {
		panic(err)
	}

	validators, err := state.Validators()
	if err != nil {
		panic(err)
	}

	for i := range validators {
		proof, err := generatorSvc.GenerateValidatorProof(ctx, fmt.Sprintf("%d", i), os.Args[1])
		if err != nil {
			panic(err)
		}
		data, err := json.Marshal(proof)
		if err != nil {
			panic(err)
		}
		fmt.Fprintf(os.Stdout, "%s\n", string(data))

		verified, err := verifierSvc.VerifyValidatorProof(ctx, proof)
		if err != nil {
			panic(err)
		}

		if !verified {
			panic(fmt.Sprintf("Validator %d not verified", i))
		}
	}
}
