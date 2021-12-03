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
	"golang.org/x/crypto/sha3"
	"testing"
)

func TestNewDLEQ(t *testing.T) {
	private, err := ecdsa.GenerateKey(theCurve, rand.Reader)
	require.NoError(t, err, "GenerateKey")
	h2x, h2y := theCurve.ScalarMult(Hx, Hy, private.D.Bytes())
	w, err := rand.Int(rand.Reader, secp256k1N)
	require.NoError(t, err, "rand.Int")
	dleq := NewDLEQ(G1, nil, G2, nil, w, private.D)

	require.Equal(t, 0, dleq.H1.X.Cmp(private.X))
	require.Equal(t, 0, dleq.H1.Y.Cmp(private.Y))
	require.Equal(t, 0, dleq.H2.X.Cmp(h2x))
	require.Equal(t, 0, dleq.H2.Y.Cmp(h2y))
}

func TestDLEQVerify(t *testing.T) {
	private, err := ecdsa.GenerateKey(theCurve, rand.Reader)
	require.NoError(t, err, "GenerateKey")
	//h2x, h2y := theCurve.ScalarMult(Hx, Hy, private.D.Bytes())
	w, err := rand.Int(rand.Reader, secp256k1N)
	require.NoError(t, err, "rand.Int")
	dleq := NewDLEQ(G1, nil, G2, nil, w, private.D)

	c, r := dleq.ChallengeAndResponse()

	ok := DLEQVerify(sha3.New256(), dleq.G1, dleq.H1, dleq.G2, dleq.H2, c, r)
	require.True(t, ok)
}

func BenchmarkDLEQ_ChallengeAndResponse(b *testing.B) {
	private, err := ecdsa.GenerateKey(theCurve, rand.Reader)
	require.NoError(b, err, "GenerateKey")
	w, err := rand.Int(rand.Reader, secp256k1N)
	require.NoError(b, err, "rand.Int")
	dleq := NewDLEQ(G1, nil, G2, nil, w, private.D)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = dleq.ChallengeAndResponse()
	}
}

func BenchmarkDLEQVerify(b *testing.B) {
	private, err := ecdsa.GenerateKey(theCurve, rand.Reader)
	require.NoError(b, err, "GenerateKey")
	w, err := rand.Int(rand.Reader, secp256k1N)
	require.NoError(b, err, "rand.Int")
	dleq := NewDLEQ(G1, nil, G2, nil, w, private.D)
	c, r := dleq.ChallengeAndResponse()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DLEQVerify(sha3.New256(), dleq.G1, dleq.H1, dleq.G2, dleq.H2, c, r)
	}
}
