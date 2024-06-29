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

package generator

import (
	"context"
	"errors"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/wealdtech/proved/types"
)

// GenerateValidatorProof generates a proof for a validator at a given block.
func (s *Service) GenerateValidatorProof(ctx context.Context,
	validatorID string,
	blockID string,
) (
	*types.ValidatorProof,
	error,
) {
	block, err := s.chain.Block(ctx, blockID)
	if err != nil {
		return nil, err
	}

	slot, err := block.Slot()
	if err != nil {
		return nil, err
	}

	validator, err := s.chain.Validator(ctx, fmt.Sprintf("%d", slot), validatorID)
	if err != nil {
		return nil, errors.Join(errors.New("failed to obtain validator"), err)
	}

	proof := &types.ValidatorProof{
		Version:        block.Version,
		ValidatorIndex: validator.Index,
		Validator:      validator.Validator,
		Slot:           slot,
	}
	switch block.Version {
	case spec.DataVersionDeneb:
		proof.Path, proof.Hashes, err = s.denebValidatorProof(ctx,
			validator,
			block.Deneb,
		)
	default:
		err = fmt.Errorf("unsupported block version %v", block.Version)
	}

	if err != nil {
		return nil, err
	}

	return proof, nil
}
