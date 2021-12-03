/*
 * Copyright (c) 2021 Stars-labs.
 * Author: darlzan@foxmail.com
 *
 * Code is licensed under GPLv3.0 License. You should have received a copy of the GNU General Public License v3.0
 * along with the go-pvss library. If not, see <http://www.gnu.org/licenses/>.
 */

package pvss

import (
	"crypto/ecdsa"
	"crypto/rand"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func TestAllPVSS(t *testing.T) {
	threshold, n := 3, 4
	dealers, pks := genDealers(n + 1)
	dealer := dealers[0]

	// 1. dealer distributes a secret
	secret := new(big.Int).SetBytes([]byte("Hello, go-pvss under ECC"))
	sharebox, err := dealer.DistributeSecret(secret, pks[1:], threshold)
	require.NoError(t, err, "DistributeSecret")
	require.Equal(t, threshold, len(sharebox.Commitments))
	require.Equal(t, n, len(sharebox.Shares))
	require.NotEqual(t, 0, sharebox.U.Cmp(secret))

	// 2. the distribution shares are publicly verifiable
	ok := VerifyDistributionShares(sharebox)
	require.True(t, ok, "VerifyDistributionShares")

	// 3. each participant can decrypts its part of share
	decShares := make([]*DecryptedShare, 0, n)
	for i, d := range dealers[1:] {
		decShare, err := d.ExtractSecretShare(sharebox)
		require.NoError(t, err, "ExtractSecretShare", i)
		require.NotNil(t, decShare, "ExtractSecretShare", i)
		decShares = append(decShares, decShare)
	}

	// 4. each decrypted share can be verified publicly
	for i, decShare := range decShares {
		ok := VerifyDecryptedShare(decShare)
		require.True(t, ok, i)
	}

	// 5. reconstruct the secret by using threshold's decrypted shares
	ds1, ds2, ds3, ds4 := decShares[0], decShares[1], decShares[2], decShares[3]
	s := ReconstructSecret([]*DecryptedShare{ds1, ds2, ds3}, sharebox.U)
	require.NotNil(t, s)
	require.Equal(t, 0, s.Cmp(secret))

	s = ReconstructSecret([]*DecryptedShare{ds4, ds2, ds3}, sharebox.U)
	require.NotNil(t, s)
	require.Equal(t, 0, s.Cmp(secret))

	s = ReconstructSecret([]*DecryptedShare{ds4, ds1, ds3}, sharebox.U)
	require.NotNil(t, s)
	require.Equal(t, 0, s.Cmp(secret))

	s = ReconstructSecret([]*DecryptedShare{ds4, ds2, ds1}, sharebox.U)
	require.NotNil(t, s)
	require.Equal(t, 0, s.Cmp(secret))

	s = ReconstructSecret([]*DecryptedShare{ds4, ds2, ds3, ds1}, sharebox.U)
	require.NotNil(t, s)
	require.Equal(t, 0, s.Cmp(secret))
}

func genDealers(n int) ([]*Dealer, []*ecdsa.PublicKey) {
	dealers := make([]*Dealer, 0, n)
	pks := make([]*ecdsa.PublicKey, 0, n)
	for i := 0; i < n; i++ {
		private, _ := ecdsa.GenerateKey(theCurve, rand.Reader)

		dealers = append(dealers, NewDealer(private))
		pks = append(pks, &private.PublicKey)
	}
	return dealers, pks
}

func BenchmarkDealer_DistributeSecret(b *testing.B) {
	threshold, n := 11, 20
	dealers, pks := genDealers(n + 1)
	dealer := dealers[0]
	secret, _ := rand.Int(rand.Reader, secp256k1N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = dealer.DistributeSecret(secret, pks[1:], threshold)
	}
}

func BenchmarkVerifyDistributionShares(b *testing.B) {
	threshold, n := 11, 20
	dealers, pks := genDealers(n + 1)
	dealer := dealers[0]
	secret, _ := rand.Int(rand.Reader, secp256k1N)
	sharebox, err := dealer.DistributeSecret(secret, pks[1:], threshold)
	require.NoError(b, err)
	decShares := make([]*DecryptedShare, 0, n)
	for i, d := range dealers[1:] {
		decShare, err := d.ExtractSecretShare(sharebox)
		require.NoError(b, err, "ExtractSecretShare", i)
		require.NotNil(b, decShare, "ExtractSecretShare", i)
		decShares = append(decShares, decShare)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyDistributionShares(sharebox)
	}
}

func BenchmarkReconstructSecret(b *testing.B) {
	threshold, n := 11, 20
	dealers, pks := genDealers(n + 1)
	dealer := dealers[0]
	secret, _ := rand.Int(rand.Reader, secp256k1N)
	sharebox, err := dealer.DistributeSecret(secret, pks[1:], threshold)
	require.NoError(b, err)
	decShares := make([]*DecryptedShare, 0, n)
	for i, d := range dealers[1:] {
		decShare, err := d.ExtractSecretShare(sharebox)
		require.NoError(b, err, "ExtractSecretShare", i)
		require.NotNil(b, decShare, "ExtractSecretShare", i)
		decShares = append(decShares, decShare)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ReconstructSecret(decShares[:threshold], sharebox.U)
	}
}
