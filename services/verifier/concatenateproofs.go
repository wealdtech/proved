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

package verifier

import (
	"context"
	"errors"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/wealdtech/proved/types"
)

// ConcatenateProofs concatenates two proofs.
// The root of the lower proof should be the value
// of the higher proof.
func ConcatenateProofs(_ context.Context,
	lower *types.Proof,
	higher *types.Proof,
) (
	*types.Proof,
	error,
) {
	if lower == nil {
		return nil, errors.New("no lower proof supplied")
	}
	if higher == nil {
		return nil, errors.New("no higher proof supplied")
	}

	steps := make([]phase0.Root, 0, len(lower.Hashes)+len(higher.Hashes))
	steps = append(steps, lower.Hashes...)
	steps = append(steps, higher.Hashes...)

	stepSides := lower.Path
	stepSides += higher.Path << len(lower.Hashes)

	return &types.Proof{
		Value:  lower.Value,
		Hashes: steps,
		Path:   stepSides,
	}, nil
}
