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
	"sync"
	"time"

	consensusclient "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/http"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/rs/zerolog"
)

// Service is a chain service.
type Service struct {
	client   consensusclient.Service
	blocks   map[string]*spec.VersionedSignedBeaconBlock
	blocksMu sync.RWMutex
	states   map[string]*spec.VersionedBeaconState
	statesMu sync.RWMutex
}

// New generates a new chain service.
func New(ctx context.Context,
	address string,
) (
	*Service,
	error,
) {
	client, err := http.New(ctx,
		http.WithLogLevel(zerolog.Disabled),
		http.WithAddress(address),
		http.WithTimeout(time.Hour),
	)
	if err != nil {
		return nil, errors.Join(errors.New("failed to access consensus client"), err)
	}

	return &Service{
		client: client,
		blocks: make(map[string]*spec.VersionedSignedBeaconBlock),
		states: make(map[string]*spec.VersionedBeaconState),
	}, nil
}
