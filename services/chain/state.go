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

func (s *Service) State(ctx context.Context,
	stateID string,
) (
	*spec.VersionedBeaconState,
	error,
) {
	s.statesMu.RLock()
	state, exists := s.states[stateID]
	s.statesMu.RUnlock()
	if exists {
		return state, nil
	}

	stateResponse, err := s.client.(consensusclient.BeaconStateProvider).BeaconState(ctx, &api.BeaconStateOpts{
		State: stateID,
	})
	if err != nil {
		return nil, errors.Join(errors.New("failed to obtain state"), err)
	}

	slot, err := stateResponse.Data.Slot()
	if err == nil {
		s.statesMu.Lock()
		s.states[fmt.Sprintf("%d", slot)] = stateResponse.Data
		s.statesMu.Unlock()
	}

	return stateResponse.Data, nil
}
