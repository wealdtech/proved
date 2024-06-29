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
	"fmt"

	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
)

// stubbedDenebBeaconState is a beacon state with most
// complex elements stubbed out for ease of generating
// validator proofs.
type stubbedDenebBeaconState struct {
	GenesisTime                      uint64
	GenesisValidatorsRoot            phase0.Root `ssz-size:"32"`
	Slot                             uint64
	ForkStub                         phase0.Root `ssz-size:"32"`
	LatestBlockHeaderStub            phase0.Root `ssz-size:"32"`
	BlockRootsStub                   phase0.Root `ssz-size:"32"`
	StateRootsStub                   phase0.Root `ssz-size:"32"`
	HistoricalRootsStub              phase0.Root `ssz-size:"32"`
	ETH1DataStub                     phase0.Root `ssz-size:"32"`
	ETH1DataVotesStub                phase0.Root `ssz-size:"32"`
	ETH1DepositIndex                 uint64
	Validators                       []*phase0.Validator `ssz-max:"1099511627776"`
	BalancesStub                     phase0.Root         `ssz-size:"32"`
	RANDOMixesStub                   phase0.Root         `ssz-size:"32"`
	SlashingsStub                    phase0.Root         `ssz-size:"32"`
	PreviousEpochParticipationStub   phase0.Root         `ssz-size:"32"`
	CurrentEpochParticipationStub    phase0.Root         `ssz-size:"32"`
	JustificationBitsStub            phase0.Root         `ssz-size:"32"`
	PreviousJustifiedCheckpointStub  phase0.Root         `ssz-size:"32"`
	CurrentJustifiedCheckpointStub   phase0.Root         `ssz-size:"32"`
	FinalizedCheckpointStub          phase0.Root         `ssz-size:"32"`
	InactivityScoresStub             phase0.Root         `ssz-size:"32"`
	CurrentSyncCommitteeStub         phase0.Root         `ssz-size:"32"`
	NextSyncCommitteeStub            phase0.Root         `ssz-size:"32"`
	LatestExecutionPayloadHeaderStub phase0.Root         `ssz-size:"32"`
	NextWithdrawalIndex              uint64
	NextWithdrawalValidatorIndex     uint64
	HistoricalSummariesStub          phase0.Root `ssz-size:"32"`
}

// denebValidatorProof generates a proof for a validator at a given block.
func (s *Service) denebValidatorProof(ctx context.Context,
	validator *apiv1.Validator,
	block *deneb.SignedBeaconBlock,
) (
	uint64,
	[]phase0.Root,
	error,
) {
	slot := fmt.Sprintf("%d", block.Message.Slot)

	s.stubbedStatesMu.RLock()
	stubbedState := s.stubbedDenebStates[slot]
	stubbedStateNodes, exists := s.stubbedStateNodes[slot]
	s.stubbedStatesMu.RUnlock()

	if !exists {
		state, err := s.chain.State(ctx, fmt.Sprintf("%d", block.Message.Slot))
		if err != nil {
			return 0, nil, err
		}

		stubbedState, err = stubDenebBeaconState(ctx, state.Deneb)
		if err != nil {
			return 0, nil, err
		}
		stubbedStateNodes, err = stubbedState.GetTree()
		if err != nil {
			return 0, nil, err
		}

		s.stubbedStatesMu.Lock()
		s.stubbedDenebStates[slot] = stubbedState
		s.stubbedStateNodes[slot] = stubbedStateNodes
		s.stubbedStatesMu.Unlock()
	}

	// Index 43 is the top of the validator tree.
	index := 43
	// Path records if we our value is on the left-hand or right-hand side of the merkle tree as we move down the levels.
	// so far our path has been LRLRR, which is encoded as binary 01011.
	path := uint64(0b01011)

	// Work down the validators tree to find our validator's (generalised) index and calculate our path back up from it.
	// Depth is based on the VALIDATOR_REGISTRY_LIMIT value in the spec.
	depth := 42
	for i := 1; i <= depth; i++ {
		if (validator.Index>>(depth-i))&1 == 1 {
			index++
			path++
		}
		if i != depth {
			index *= 2
			path *= 2
		}
	}

	validatorProof, err := stubbedStateNodes.Prove(index)
	if err != nil {
		return 0, nil, err
	}

	// The proof does not include the leaf value (bug in fastssz when the leaf is an intermediate node), so add in manually.
	if validatorProof.Leaf == nil {
		validatorRoot, err := stubbedState.Validators[validator.Index].HashTreeRoot()
		if err != nil {
			return 0, nil, err
		}
		validatorProof.Leaf = validatorRoot[:]
	}

	proofs := make([]phase0.Root, len(validatorProof.Hashes))
	for i := range validatorProof.Hashes {
		copy(proofs[i][:], validatorProof.Hashes[i])
	}

	return path, proofs, nil
}

//nolint:gocyclo
func stubDenebBeaconState(_ context.Context,
	state *deneb.BeaconState,
) (
	*stubbedDenebBeaconState,
	error,
) {
	var err error
	hh := ssz.DefaultHasherPool.Get()
	defer ssz.DefaultHasherPool.Put(hh)

	stubbedState := &stubbedDenebBeaconState{}

	// Field 1.
	stubbedState.GenesisTime = state.GenesisTime

	// Field 2.
	stubbedState.GenesisValidatorsRoot = state.GenesisValidatorsRoot

	// Field 3.
	stubbedState.Slot = uint64(state.Slot)

	// Field 4.
	stubbedState.ForkStub, err = state.Fork.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	// Field 5.
	stubbedState.LatestBlockHeaderStub, err = state.LatestBlockHeader.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	// Field 6.
	{
		hh.Reset()
		subIndx := hh.Index()
		for _, i := range state.BlockRoots {
			hh.Append(i[:])
		}
		hh.Merkleize(subIndx)
		stubbedState.BlockRootsStub, err = hh.HashRoot()
		if err != nil {
			return nil, err
		}
	}

	// Field 7.
	{
		hh.Reset()
		subIndx := hh.Index()
		for _, i := range state.StateRoots {
			hh.Append(i[:])
		}
		hh.Merkleize(subIndx)
		stubbedState.StateRootsStub, err = hh.HashRoot()
		if err != nil {
			return nil, err
		}
	}

	// Field 8.
	{
		hh.Reset()
		subIndx := hh.Index()
		for _, i := range state.HistoricalRoots {
			hh.Append(i[:])
		}
		numItems := uint64(len(state.HistoricalRoots))
		hh.MerkleizeWithMixin(subIndx, numItems, 16777216)
		stubbedState.HistoricalRootsStub, err = hh.HashRoot()
		if err != nil {
			return nil, err
		}
	}

	// Field 9.
	stubbedState.ETH1DataStub, err = state.ETH1Data.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	// Field 10.
	{
		hh.Reset()
		subIndx := hh.Index()
		for _, i := range state.ETH1DataVotes {
			if err := i.HashTreeRootWith(hh); err != nil {
				return nil, err
			}
		}
		hh.MerkleizeWithMixin(subIndx, uint64(len(state.ETH1DataVotes)), 2048)
		stubbedState.ETH1DataVotesStub, err = hh.HashRoot()
		if err != nil {
			return nil, err
		}
	}

	// Field 11.
	stubbedState.ETH1DepositIndex = state.ETH1DepositIndex

	// Field 12.
	stubbedState.Validators = state.Validators

	// Field 13.
	{
		hh.Reset()
		subIndx := hh.Index()
		for _, i := range state.Balances {
			hh.AppendUint64(uint64(i))
		}
		hh.FillUpTo32()
		numItems := uint64(len(state.Balances))
		hh.MerkleizeWithMixin(subIndx, numItems, ssz.CalculateLimit(1099511627776, numItems, 8))
		stubbedState.BalancesStub, err = hh.HashRoot()
		if err != nil {
			return nil, err
		}
	}

	// Field 14.
	{
		hh.Reset()
		subIndx := hh.Index()
		for _, i := range state.RANDAOMixes {
			hh.Append(i[:])
		}
		hh.Merkleize(subIndx)
		stubbedState.RANDOMixesStub, err = hh.HashRoot()
		if err != nil {
			return nil, err
		}
	}

	// Field 15.
	{
		hh.Reset()
		subIndx := hh.Index()
		for _, i := range state.Slashings {
			hh.AppendUint64(uint64(i))
		}
		hh.Merkleize(subIndx)
		stubbedState.SlashingsStub, err = hh.HashRoot()
		if err != nil {
			return nil, err
		}
	}

	// Field 16.
	{
		hh.Reset()
		subIndx := hh.Index()
		for _, i := range state.PreviousEpochParticipation {
			hh.AppendUint8(uint8(i))
		}
		hh.FillUpTo32()
		numItems := uint64(len(state.PreviousEpochParticipation))
		hh.MerkleizeWithMixin(subIndx, numItems, ssz.CalculateLimit(1099511627776, numItems, 1))
		stubbedState.PreviousEpochParticipationStub, err = hh.HashRoot()
		if err != nil {
			return nil, err
		}
	}

	// Field 17.
	{
		hh.Reset()
		subIndx := hh.Index()
		for _, i := range state.CurrentEpochParticipation {
			hh.AppendUint8(uint8(i))
		}
		hh.FillUpTo32()
		numItems := uint64(len(state.CurrentEpochParticipation))
		hh.MerkleizeWithMixin(subIndx, numItems, ssz.CalculateLimit(1099511627776, numItems, 1))
		stubbedState.CurrentEpochParticipationStub, err = hh.HashRoot()
		if err != nil {
			return nil, err
		}
	}

	// Field 18.
	{
		hh.Reset()
		hh.PutBytes(state.JustificationBits)
		stubbedState.JustificationBitsStub, err = hh.HashRoot()
		if err != nil {
			return nil, err
		}
	}

	stubbedState.PreviousJustifiedCheckpointStub, err = state.PreviousJustifiedCheckpoint.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	stubbedState.CurrentJustifiedCheckpointStub, err = state.CurrentJustifiedCheckpoint.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	stubbedState.FinalizedCheckpointStub, err = state.FinalizedCheckpoint.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	{
		hh.Reset()
		subIndx := hh.Index()
		for _, i := range state.InactivityScores {
			hh.AppendUint64(i)
		}
		hh.FillUpTo32()
		numItems := uint64(len(state.InactivityScores))
		hh.MerkleizeWithMixin(subIndx, numItems, ssz.CalculateLimit(1099511627776, numItems, 8))
		stubbedState.InactivityScoresStub, err = hh.HashRoot()
		if err != nil {
			return nil, err
		}
	}

	stubbedState.CurrentSyncCommitteeStub, err = state.CurrentSyncCommittee.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	stubbedState.NextSyncCommitteeStub, err = state.NextSyncCommittee.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	stubbedState.LatestExecutionPayloadHeaderStub, err = state.LatestExecutionPayloadHeader.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	stubbedState.NextWithdrawalIndex = uint64(state.NextWithdrawalIndex)

	stubbedState.NextWithdrawalValidatorIndex = uint64(state.NextWithdrawalValidatorIndex)

	{
		hh.Reset()
		subIndx := hh.Index()
		for _, i := range state.HistoricalSummaries {
			if err := i.HashTreeRootWith(hh); err != nil {
				return nil, err
			}
		}
		hh.MerkleizeWithMixin(subIndx, uint64(len(state.HistoricalSummaries)), 16777216)
		stubbedState.HistoricalSummariesStub, err = hh.HashRoot()
		if err != nil {
			return nil, err
		}
	}

	return stubbedState, nil
}
