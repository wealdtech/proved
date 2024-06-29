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

package verifier_test

import (
	"context"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"
	"github.com/wealdtech/proved/services/verifier"
	"github.com/wealdtech/proved/types"
)

func TestConcatenateProofs(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name   string
		lower  *types.Proof
		higher *types.Proof
		res    *types.Proof
		root   phase0.Root
		err    string
	}{
		{
			name:   "EmptyLower",
			higher: &types.Proof{},
			err:    "no lower proof supplied",
		},
		{
			name:  "EmptyHigher",
			lower: &types.Proof{},
			err:   "no higher proof supplied",
		},
		{
			name: "StateGivenBlock",
			lower: &types.Proof{
				Value: root("f6f1645a5a07095f12718576310ce02d01100c05213041f56a6ca4e350e2a045"),
				Path:  24189256493891,
				Hashes: []phase0.Root{
					root("55b78a593c0dcdbaa724ba563f11369f7939e2186c9b6f058a141ab925274169"),
					root("eefc160ea9256e56212233c892403b93c3346d008dc2da96939e541d7e77d74b"),
					root("db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71"),
					root("c78009fdf07fc56a11f122370658a353aaa542ed63e44c4bc15ff4cd105ab33c"),
					root("536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c"),
					root("9efde052aa15429fae05bad4d0b1d7c64da64d03d7a1854a588c2cb8430c0d30"),
					root("1e97c660545feb1164116703c8bb1b11052a7fefdfa03fd2d61375ce6fdc231f"),
					root("87eb0ddba57e35f6d286673802a4af5975e22506c7cf4c64bb6be5ee11527f2c"),
					root("e3becdc3e0b50c531106e507dbfb559136a1354de7c289efeebc4e6fda7e3b1a"),
					root("d05818f92b867f83dbc1dab17d160b8047febb2d8c414435159ce360781b3e25"),
					root("ffff0ad7e659772f9534c195c815efc4014ef1e1daed4404c06385d11192e92b"),
					root("d57027e3fd6cbbb2d676b7f88a364b68d30b84552b97153b5c12beec73a2767b"),
					root("b7d05f875f140027ef5118a2247bbb84ce8f2f0f1123623085daf7960c329f5f"),
					root("67b7b2b9e41c12449119fd40f067a8c20ea807ed322f0f5b084c413baf5baa64"),
					root("833a3951946543d5f5312d93bf7991f8ff8c74bcb1ac413c42d21de2f3961d87"),
					root("d49a7502ffcfb0340b1d7885688500ca308161a7f96b62df9d083b71fcc8f2bb"),
					root("8fe6b1689256c0d385f42f5bbe2027a22c1996e110ba97c171d3e5948de92beb"),
					root("115a836b6bb731eb94b524eaf603c9d9d563e3ce6e7e0a5320c31bc2687bd718"),
					root("95eec8b2e541cad4e91de38385f2e046619f54496c2382cb6cacd5b98c26f5a4"),
					root("903653b6e276c6aa6ae3860bb5d6e8c52466cfdddc1fa19664f69f69e67ccb61"),
					root("cddba7b592e3133393c16194fac7431abf2f5485ed711db282183c819e08ebaa"),
					root("8a8d7fe3af8caa085a7639a832001457dfb9128a8061142ad0335629ff23ff9c"),
					root("feb3c337d7a51a6fbf00b9e34c52e1c9195c969bd4e7a0bfd51d5c5bed9c1167"),
					root("e71f0aa83cc32edfbefa9f4d3e0174ca85182eec9f3a09f6a6c0df6377a510d7"),
					root("31206fa80a50bb6abe29085058f16212212a60eec8f049fecb92d8c8e0a84bc0"),
					root("21352bfecbeddde993839f614c3dac0a3ee37543f9b412b16199dc158e23b544"),
					root("619e312724bb6d7c3153ed9de791d764a366b389af13c58bf8a8d90481a46765"),
					root("7cdd2986268250628d0c10e385c58c6191e6fbe05191bcc04f133f2cea72c1c4"),
					root("848930bd7ba8cac54661072113fb278869e07bb8587f91392933374d017bcbe1"),
					root("8869ff2c22b28cc10510d9853292803328be4fb0e80495e8bb8d271f5b889636"),
					root("b5fe28e79f1b850f8658246ce9b6a1e7b49fc06db7143e8fe0b4f2b0c5523a5c"),
					root("985e929f70af28d0bdd1a90a808f977f597c7c778c489e98d3bd8910d31ac0f7"),
					root("c6f67e02e6e4e1bdefb994c6098953f34636ba2b6ca20a4721d2b26a886722ff"),
					root("1c9a7e5ff1cf48b4ad1582d3f4e4a1004f3b20d8c5a2b71387a4254ad933ebc5"),
					root("2f075ae229646b6f6aed19a5e372cf295081401eb893ff599b3f9acc0c0d3e7d"),
					root("328921deb59612076801e8cd61592107b5c67c79b846595cc6320c395b46362c"),
					root("bfb909fdb236ad2411b4e4883810a074b840464689986c3f8a8091827e17c327"),
					root("55d8fb3687ba3ba49f342c77f5a1f89bec83d811446e1a467139213d640b6a74"),
					root("f7210d4f8e7e1039790e7bf4efa207555a10a6db1dd4b95da313aaa88b88fe76"),
					root("ad21b516cbc645ffe34ab5de1c8aef8cd4e7f8d2b51e8e1456adc7563cda206f"),
					root("446b0a0000000000000000000000000000000000000000000000000000000000"),
					root("7777070000000000000000000000000000000000000000000000000000000000"),
					root("c0e6408e4321d62dc0dc7e677d70ed79fafd3ddc445e9e8f393f50d17b716615"),
					root("63820f7a3371352f03a4b5980cf5f4a69a04dbe09209feb75bf53c98136d56e5"),
					root("98cbe1672a8fffce59f8b8322daa0f507a90bcb2a90283e9b06d4072699cb899"),
					root("8df5d4e1232ea705e04b0e94872d9a61dccbb1d9e64931497ebd0053e0b8a0d7"),
				},
			},
			higher: &types.Proof{
				Value: root("a9c660d2d401587dd5a65840ede6412a4933e78c6db95df4e8c80cd8a255d569"),
				Path:  3,
				Hashes: []phase0.Root{
					root("a3519c7711d83dba3c109bccc465641108e28864a2e207d3f01c61c19ce9e88b"),
					root("0718b2456b58b3c9e1c9b0a7aef7e6a1972aa2c943ccef478bc766c6cceffafb"),
					root("d44a44538625d15a0273de2d5298d1a509f29292b2c22864d2e48b6caf881295"),
				},
			},
			root: root("0f852649205b79a4c1a92598a50bdddd788626efdd5c59b920d0557f6b84b5ad"),
			res: &types.Proof{
				Value: root("f6f1645a5a07095f12718576310ce02d01100c05213041f56a6ca4e350e2a045"),
				Path:  235295489026883,
				Hashes: []phase0.Root{
					root("55b78a593c0dcdbaa724ba563f11369f7939e2186c9b6f058a141ab925274169"),
					root("eefc160ea9256e56212233c892403b93c3346d008dc2da96939e541d7e77d74b"),
					root("db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71"),
					root("c78009fdf07fc56a11f122370658a353aaa542ed63e44c4bc15ff4cd105ab33c"),
					root("536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c"),
					root("9efde052aa15429fae05bad4d0b1d7c64da64d03d7a1854a588c2cb8430c0d30"),
					root("1e97c660545feb1164116703c8bb1b11052a7fefdfa03fd2d61375ce6fdc231f"),
					root("87eb0ddba57e35f6d286673802a4af5975e22506c7cf4c64bb6be5ee11527f2c"),
					root("e3becdc3e0b50c531106e507dbfb559136a1354de7c289efeebc4e6fda7e3b1a"),
					root("d05818f92b867f83dbc1dab17d160b8047febb2d8c414435159ce360781b3e25"),
					root("ffff0ad7e659772f9534c195c815efc4014ef1e1daed4404c06385d11192e92b"),
					root("d57027e3fd6cbbb2d676b7f88a364b68d30b84552b97153b5c12beec73a2767b"),
					root("b7d05f875f140027ef5118a2247bbb84ce8f2f0f1123623085daf7960c329f5f"),
					root("67b7b2b9e41c12449119fd40f067a8c20ea807ed322f0f5b084c413baf5baa64"),
					root("833a3951946543d5f5312d93bf7991f8ff8c74bcb1ac413c42d21de2f3961d87"),
					root("d49a7502ffcfb0340b1d7885688500ca308161a7f96b62df9d083b71fcc8f2bb"),
					root("8fe6b1689256c0d385f42f5bbe2027a22c1996e110ba97c171d3e5948de92beb"),
					root("115a836b6bb731eb94b524eaf603c9d9d563e3ce6e7e0a5320c31bc2687bd718"),
					root("95eec8b2e541cad4e91de38385f2e046619f54496c2382cb6cacd5b98c26f5a4"),
					root("903653b6e276c6aa6ae3860bb5d6e8c52466cfdddc1fa19664f69f69e67ccb61"),
					root("cddba7b592e3133393c16194fac7431abf2f5485ed711db282183c819e08ebaa"),
					root("8a8d7fe3af8caa085a7639a832001457dfb9128a8061142ad0335629ff23ff9c"),
					root("feb3c337d7a51a6fbf00b9e34c52e1c9195c969bd4e7a0bfd51d5c5bed9c1167"),
					root("e71f0aa83cc32edfbefa9f4d3e0174ca85182eec9f3a09f6a6c0df6377a510d7"),
					root("31206fa80a50bb6abe29085058f16212212a60eec8f049fecb92d8c8e0a84bc0"),
					root("21352bfecbeddde993839f614c3dac0a3ee37543f9b412b16199dc158e23b544"),
					root("619e312724bb6d7c3153ed9de791d764a366b389af13c58bf8a8d90481a46765"),
					root("7cdd2986268250628d0c10e385c58c6191e6fbe05191bcc04f133f2cea72c1c4"),
					root("848930bd7ba8cac54661072113fb278869e07bb8587f91392933374d017bcbe1"),
					root("8869ff2c22b28cc10510d9853292803328be4fb0e80495e8bb8d271f5b889636"),
					root("b5fe28e79f1b850f8658246ce9b6a1e7b49fc06db7143e8fe0b4f2b0c5523a5c"),
					root("985e929f70af28d0bdd1a90a808f977f597c7c778c489e98d3bd8910d31ac0f7"),
					root("c6f67e02e6e4e1bdefb994c6098953f34636ba2b6ca20a4721d2b26a886722ff"),
					root("1c9a7e5ff1cf48b4ad1582d3f4e4a1004f3b20d8c5a2b71387a4254ad933ebc5"),
					root("2f075ae229646b6f6aed19a5e372cf295081401eb893ff599b3f9acc0c0d3e7d"),
					root("328921deb59612076801e8cd61592107b5c67c79b846595cc6320c395b46362c"),
					root("bfb909fdb236ad2411b4e4883810a074b840464689986c3f8a8091827e17c327"),
					root("55d8fb3687ba3ba49f342c77f5a1f89bec83d811446e1a467139213d640b6a74"),
					root("f7210d4f8e7e1039790e7bf4efa207555a10a6db1dd4b95da313aaa88b88fe76"),
					root("ad21b516cbc645ffe34ab5de1c8aef8cd4e7f8d2b51e8e1456adc7563cda206f"),
					root("446b0a0000000000000000000000000000000000000000000000000000000000"),
					root("7777070000000000000000000000000000000000000000000000000000000000"),
					root("c0e6408e4321d62dc0dc7e677d70ed79fafd3ddc445e9e8f393f50d17b716615"),
					root("63820f7a3371352f03a4b5980cf5f4a69a04dbe09209feb75bf53c98136d56e5"),
					root("98cbe1672a8fffce59f8b8322daa0f507a90bcb2a90283e9b06d4072699cb899"),
					root("8df5d4e1232ea705e04b0e94872d9a61dccbb1d9e64931497ebd0053e0b8a0d7"),
					root("a3519c7711d83dba3c109bccc465641108e28864a2e207d3f01c61c19ce9e88b"),
					root("0718b2456b58b3c9e1c9b0a7aef7e6a1972aa2c943ccef478bc766c6cceffafb"),
					root("d44a44538625d15a0273de2d5298d1a509f29292b2c22864d2e48b6caf881295"),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := verifier.ConcatenateProofs(ctx, test.lower, test.higher)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.res, res)
				proven, err := verifier.VerifyProof(ctx, test.root, res)
				require.NoError(t, err)
				require.True(t, proven)
			}
		})
	}
}
