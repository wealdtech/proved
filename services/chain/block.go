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
	"errors"
	"fmt"

	consensusclient "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	"github.com/attestantio/go-eth2-client/spec"
)

func (s *Service) Block(ctx context.Context,
	blockID string,
) (
	*spec.VersionedSignedBeaconBlock,
	error,
) {
	s.blocksMu.RLock()
	block, exists := s.blocks[blockID]
	s.blocksMu.RUnlock()
	if exists {
		return block, nil
	}

	blockResponse, err := s.client.(consensusclient.SignedBeaconBlockProvider).SignedBeaconBlock(ctx, &api.SignedBeaconBlockOpts{
		Block: blockID,
	})
	if err != nil {
		return nil, errors.Join(errors.New("failed to obtain block"), err)
	}

	slot, err := blockResponse.Data.Slot()
	if err == nil {
		s.blocksMu.Lock()
		s.blocks[fmt.Sprintf("%d", slot)] = blockResponse.Data
		s.blocksMu.Unlock()
	}

	return blockResponse.Data, nil
}
