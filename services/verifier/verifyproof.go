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
	"bytes"
	"context"
	"crypto/sha256"
	"errors"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/wealdtech/proved/types"
)

// VerifyProof verifies a proof, returning true if the
// proof is verified and otherwise false.
func VerifyProof(_ context.Context,
	root phase0.Root,
	proof *types.Proof,
) (
	bool,
	error,
) {
	hash := proof.Value
	h := sha256.New()

	// Take a copy of the path as we alter it as we go along.
	path := proof.Path
	for i := range proof.Hashes {
		h.Reset()
		switch {
		case proof.Path>>i&1 == 1:
			// case path&1 == 1:
			if _, err := h.Write(proof.Hashes[i][:]); err != nil {
				return false, errors.Join(errors.New("failed to write proof step (left)"), err)
			}
			if _, err := h.Write(hash[:]); err != nil {
				return false, errors.Join(errors.New("failed to write hash (left)"), err)
			}
		default:
			if _, err := h.Write(hash[:]); err != nil {
				return false, errors.Join(errors.New("failed to write hash (right)"), err)
			}
			if _, err := h.Write(proof.Hashes[i][:]); err != nil {
				return false, errors.Join(errors.New("failed to write proof step (right)"), err)
			}
		}
		copy(hash[:], h.Sum(nil))

		path >>= 1
	}

	return bytes.Equal(hash[:], root[:]), nil
}
