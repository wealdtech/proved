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

import "github.com/attestantio/go-eth2-client/spec/phase0"

// Proof contains the elements of a proof.
type Proof struct {
	// Value is the value we are attempting to prove.
	Value phase0.Root
	// Path are the bits stating which side of the hash each step falls on.
	Path uint64
	// Hashes are the intermediate hashes.
	Hashes []phase0.Root
}
