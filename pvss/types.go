/*
 * Copyright (c) 2021-2021 Stars-labs.
 * Author: darlzan@foxmail.com
 *
 * Code is licensed under GPLv3.0 License. You should have received a copy of the GNU General Public License v3.0
 * along with the go-pvss library. If not, see <http://www.gnu.org/licenses/>.
 */

package pvss

import (
	"crypto/ecdsa"
	"math/big"
)

type Point struct {
	X *big.Int
	Y *big.Int
}

type DistributionSharesBox struct {
	Commitments []*Point
	Shares      []*Share
	U           *big.Int
}

// Share includes the encrypted share and dleq information,
// DLEQ(G1,H1,G2,H2) == > DLEQ(H,X,PK,S)
// H is the second base point of ecc curve, X can be calculated both by dealer and participants( need the Commitments and Position),
// so H,X are not included in the struct directly
type Share struct {
	PK        *ecdsa.PublicKey
	Position  int
	S         *Point // Share
	challenge *big.Int
	response  *big.Int
}

// DecryptedShare includes the decrypted share and dleq information,
// DLEQ(G1,H1,G2,H2) ==> DLEQ(G,PK,S,Y)
type DecryptedShare struct {
	PK        *ecdsa.PublicKey
	Position  int
	S         *Point
	Y         *Point
	challenge *big.Int
	response  *big.Int
}
