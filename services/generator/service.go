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
	"sync"

	ssz "github.com/ferranbt/fastssz"
	"github.com/wealdtech/proved/services/chain"
)

type Service struct {
	chain *chain.Service

	// stubbedStatesMu covers all access to stubbed state maps, both
	// for the structs and for the SSZ nodes.
	stubbedStatesMu    sync.RWMutex
	stubbedDenebStates map[string]*stubbedDenebBeaconState
	stubbedStateNodes  map[string]*ssz.Node
}

func New(_ context.Context,
	chainSvc *chain.Service,
) (
	*Service,
	error,
) {
	return &Service{
		chain:              chainSvc,
		stubbedDenebStates: make(map[string]*stubbedDenebBeaconState),
		stubbedStateNodes:  make(map[string]*ssz.Node),
	}, nil
}
