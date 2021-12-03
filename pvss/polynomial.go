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
	"math/big"
)

type Polynomial struct {
	coefficients []*big.Int
}

// InitPolynomial initialises a polynomial of the given degree,
// all coefficients are less than the given n,
// and the n should be the order of the base point of the selected ECC curve.
func InitPolynomial(degree int, n *big.Int) (*Polynomial, error) {
	// there will be degree+1 coefficients
	poly := &Polynomial{coefficients: make([]*big.Int, degree+1)}
	for i := 0; i <= degree; i++ {
		a, err := rand.Int(rand.Reader, n)
		if err != nil {
			return nil, err
		}
		poly.coefficients[i] = a
	}
	return poly, nil
}

// GetValue evaluates `P(x) mod n` and then returns the result.
// n should be the order of the base point of the selected ECC curve.
func (poly *Polynomial) GetValue(x, n *big.Int) *big.Int {
	xi := new(big.Int).Set(x)
	sum := new(big.Int)
	sum.Add(sum, poly.coefficients[0])

	aixi := new(big.Int) // for reuse
	for i := 1; i < len(poly.coefficients); i++ {
		aixi.SetInt64(0)
		aixi.Mul(poly.coefficients[i], xi) // ai * xi
		sum.Add(sum, aixi)
		sum.Mod(sum, n)
		xi.Mul(xi, x)
		xi.Mod(xi, n)
	}
	return sum
}
