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

package chain

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	consensusclient "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

func (s *Service) Validator(ctx context.Context,
	stateID string,
	validatorID string,
) (
	*apiv1.Validator,
	error,
) {
	opts := &api.ValidatorsOpts{
		State: stateID,
	}

	// Sort out validator ID.
	if strings.HasPrefix(validatorID, "0x") {
		var pubKey phase0.BLSPubKey
		data, err := hex.DecodeString(strings.TrimPrefix(validatorID, "0x"))
		if err != nil {
			return nil, errors.New("invalid public key")
		}
		copy(pubKey[:], data)
		opts.PubKeys = []phase0.BLSPubKey{pubKey}
	} else {
		index, err := strconv.ParseUint(validatorID, 10, 64)
		if err != nil {
			return nil, errors.New("invalid index")
		}
		opts.Indices = []phase0.ValidatorIndex{phase0.ValidatorIndex(index)}
	}

	validatorsResponse, err := s.client.(consensusclient.ValidatorsProvider).Validators(ctx, opts)
	if err != nil {
		return nil, errors.Join(errors.New("failed to obtain validator"), err)
	}

	for _, v := range validatorsResponse.Data {
		return v, nil
	}

	return nil, errors.New("unknown validator")
}
