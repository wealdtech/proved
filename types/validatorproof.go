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

package types

import (
	"encoding/json"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// ValidatorProof holds a validator plus its proof at a given slot.
type ValidatorProof struct {
	Validator      *phase0.Validator
	ValidatorIndex phase0.ValidatorIndex
	Slot           phase0.Slot
	Version        spec.DataVersion
	Path           uint64
	Hashes         []phase0.Root
}

// validatorProofJSON is the JSON representation of the struct.
type validatorProofJSON struct {
	Validator      *phase0.Validator     `json:"validator"`
	ValidatorIndex phase0.ValidatorIndex `json:"validator_index"`
	Slot           phase0.Slot           `json:"slot"`
	Version        spec.DataVersion      `json:"version"`
	Path           string                `json:"path"`
	Hashes         []phase0.Root         `json:"hashes"`
}

func (v *ValidatorProof) MarshalJSON() ([]byte, error) {
	return json.Marshal(&validatorProofJSON{
		Validator:      v.Validator,
		ValidatorIndex: v.ValidatorIndex,
		Slot:           v.Slot,
		Version:        v.Version,
		Path:           fmt.Sprintf("%d", v.Path),
		Hashes:         v.Hashes,
	})
}
