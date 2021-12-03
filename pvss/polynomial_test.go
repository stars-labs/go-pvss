/*
 * Copyright (c) 2021 Stars-labs.
 * Author: darlzan@foxmail.com
 *
 * Code is licensed under GPLv3.0 License. You should have received a copy of the GNU General Public License v3.0
 * along with the go-pvss library. If not, see <http://www.gnu.org/licenses/>.
 */

package pvss

import (
	"crypto/rand"
	"github.com/stars-labs/go-pvss/crypto/secp256k1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func TestInit(t *testing.T) {
	curve := secp256k1.S256()
	p, err := InitPolynomial(10, curve.N)
	require.NoError(t, err)
	require.Equal(t, 10+1, len(p.coefficients))
	for _, coefficient := range p.coefficients {
		t.Log(coefficient.Text(16))
		require.True(t, coefficient.Cmp(curve.N) < 0)
	}
}
func TestPolynomial_GetValue(t *testing.T) {
	// a_0 = 3, a_1 = 2, a_2 = 2, a_3 = 4
	p := &Polynomial{coefficients: make([]*big.Int, 4)}
	p.coefficients[0] = new(big.Int).SetInt64(3)
	p.coefficients[1] = new(big.Int).SetInt64(2)
	p.coefficients[2] = new(big.Int).SetInt64(2)
	p.coefficients[3] = new(big.Int).SetInt64(4)

	curve := secp256k1.S256()
	x := new(big.Int)
	// P(0) == 3
	assert.EqualValues(t, 3, p.GetValue(x, curve.N).Int64())
	// P(1) == 11
	x.SetInt64(1)
	assert.EqualValues(t, 11, p.GetValue(x, curve.N).Int64())
	// P(2) == 47
	x.SetInt64(2)
	assert.EqualValues(t, 47, p.GetValue(x, curve.N).Int64())
	// P(3) == 135
	x.SetInt64(3)
	assert.EqualValues(t, 135, p.GetValue(x, curve.N).Int64())
}

func BenchmarkPolynomial_GetValue(b *testing.B) {
	curve := secp256k1.S256()
	p, _ := InitPolynomial(10, curve.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x, _ := rand.Int(rand.Reader, curve.N)
		p.GetValue(x, curve.N)
	}
}
