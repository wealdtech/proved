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
	"fmt"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/wealdtech/proved/types"
)

// VerifyValidatorProof verifies a proof for a validator at a given block.
func (s *Service) VerifyValidatorProof(ctx context.Context,
	proof *types.ValidatorProof,
) (
	bool,
	error,
) {
	block, err := s.chain.Block(ctx, fmt.Sprintf("%d", proof.Slot))
	if err != nil {
		return false, err
	}

	var verified bool
	switch block.Version {
	case spec.DataVersionDeneb:
		verified, err = s.denebValidatorProof(ctx, proof, block)
	default:
		err = fmt.Errorf("unsupported block version %v", block.Version)
	}

	if err != nil {
		return false, err
	}

	return verified, nil
}
