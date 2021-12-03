/*
 * Copyright (c) 2021-2021 Stars-labs.
 * Author: darlzan@foxmail.com
 *
 * Code is licensed under GPLv3.0 License. You should have received a copy of the GNU General Public License v3.0
 * along with the go-pvss library. If not, see <http://www.gnu.org/licenses/>.
 */

package pvss

import (
	"golang.org/x/crypto/sha3"
	"hash"
	"math/big"
)

// DLEQ implements Chaum and Pedersen [CP93] scheme under ECC.
// The paper:
// [CP93] D. Chaum and T. P. Pedersen. Wallet databases with observers. In Advances in Cryptology—CRYPTO ’92,
// volume 740 of Lecture Notes in Computer Science, pages 89–105, Berlin, 1993. Springer-Verlag.
//
// Under ECC scheme, we denote that G1,G2 are two generators of the selected curve, and no one knows the relationship of G1 and G2,
// n is the order of the curve's base point.
// The prover needs to prove that he knows alpha such that H1 = alpha · G1, H2 = alpha · G2.
// We denote this protocol by DLEQ(G1,H1,G2,H2).
//
// And by using a secure hash function, we can turn the interactive protocol to a non-interactive protocol.
//
// - The prover selects a random omega (w), calculates H1 = alpha · G1, H2 = alpha · G2, A1 = w · G1, A2 = w · G2
// - The prover then calculates Hash(H1,H2,A1,A2) as challenge c,
// - and calculates a response r = (w - alpha * c) mod n,
// - The verifier calculates A1 = r · G1 + c · H1, A2 = r · G2 + c · H2, and verify that Hash(H1,H2,A1,A2) == c
type DLEQ struct {
	G1 *Point
	H1 *Point
	G2 *Point
	H2 *Point

	w     *big.Int
	alpha *big.Int
	r     *big.Int
}

// NewDLEQ initialises DLEQ(G1,H1,G2,H2), where H1, H2 can be nil.
// when H1,H2 are nil, then they will be calculated by H1 = alpha · G1, H2 = alpha · G2 .
// H1,H2 should never be nil on the result.
func NewDLEQ(G1, H1, G2, H2 *Point, w, alpha *big.Int) *DLEQ {
	if H1 == nil {
		h1x, h1y := theCurve.ScalarMult(G1.X, G1.Y, alpha.Bytes())
		H1 = &Point{X: h1x, Y: h1y}
	}
	if H2 == nil {
		h2x, h2y := theCurve.ScalarMult(G2.X, G2.Y, alpha.Bytes())
		H2 = &Point{X: h2x, Y: h2y}
	}
	return &DLEQ{
		G1:    G1,
		H1:    H1,
		G2:    G2,
		H2:    H2,
		w:     w,
		alpha: alpha,
		r:     nil,
	}
}

// ChallengeAndResponse calculates and returns the challenge and response,
// A1 := w·G1 , A2 := w·G2 ,
// c := Hash(H1,H2,A1,A2) mod n ,
// r := (w - alpha*c) mod n .
func (d *DLEQ) ChallengeAndResponse() (c, r *big.Int) {
	// A1 := w·G1 A2 := w·G2
	a1x, a1y := theCurve.ScalarMult(d.G1.X, d.G1.Y, d.w.Bytes())
	//log.Printf("Prover A1: %s, %s\n", a1x.Text(16), a1y.Text(16))
	a2x, a2y := theCurve.ScalarMult(d.G2.X, d.G2.Y, d.w.Bytes())
	//log.Printf("Prover A2: %s, %s\n", a2x.Text(16), a2y.Text(16))

	// c := Hash(H1,H2,A1,A2) mod n
	hasher := sha3.New256()
	c = HashMod(secp256k1N, hasher, d.H1.X, d.H1.Y, d.H2.X, d.H2.Y, a1x, a1y, a2x, a2y)
	// r := (w - alpha*c) mod n
	r = Response(d.w, d.alpha, c, secp256k1N)
	return
}

// Response calculates and returns r := (w - alpha*c) mod n
func Response(w, alpha, c, n *big.Int) *big.Int {
	r := new(big.Int).Mul(alpha, c) // alpha * c
	r.Mod(r, n)                     // (alpha * c) mod n
	r.Sub(w, r)                     // w - alpha*c
	r.Mod(r, n)
	return r
}

// DLEQVerify calculates A1 = r · G1 + c · H1, A2 = r · G2 + c · H2, and verify that Hash(H1,H2,A1,A2) == c
func DLEQVerify(hasher hash.Hash, G1, H1, G2, H2 *Point, c, r *big.Int) bool {
	//  A1 := r·G1 + c·H1,   A2 := r·G2 + c·H2
	a1x, a1y := theCurve.ScalarMult(G1.X, G1.Y, r.Bytes())
	h1cx, h1cy := theCurve.ScalarMult(H1.X, H1.Y, c.Bytes())
	a1x, a1y = theCurve.Add(a1x, a1y, h1cx, h1cy)
	//log.Printf("Verify A1: %s, %s\n", a1x.Text(16), a1y.Text(16))

	a2x, a2y := theCurve.ScalarMult(G2.X, G2.Y, r.Bytes())
	h2cx, h2cy := theCurve.ScalarMult(H2.X, H2.Y, c.Bytes())
	a2x, a2y = theCurve.Add(a2x, a2y, h2cx, h2cy)
	//log.Printf("Verify A2: %s, %s\n", a2x.Text(16), a2y.Text(16))

	localChallenge := HashMod(secp256k1N, hasher, H1.X, H1.Y, H2.X, H2.Y, a1x, a1y, a2x, a2y)
	return localChallenge.Cmp(c) == 0
}
