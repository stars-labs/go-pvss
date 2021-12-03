/*
 * Copyright (c) 2021 Stars-labs.
 * Author: darlzan@foxmail.com
 *
 * Code is licensed under GPLv3.0 License. You should have received a copy of the GNU General Public License v3.0
 * along with the go-pvss library. If not, see <http://www.gnu.org/licenses/>.
 */

package pvss

import (
	"crypto/elliptic"
	"github.com/stars-labs/go-pvss/crypto/secp256k1"
	"math/big"
)

var (
	secp256k1N                = new(big.Int).Set(secp256k1.S256().N)
	theCurve   elliptic.Curve = secp256k1.S256()
)

var (
	// Generator point Hx,Hy of secp256k1
	//
	// Used as generator point for the value in Pedersen Commitments.
	// Created as NUMS (nothing-up-my-sleeve) curve point from SHA256 hash of G.
	// Details: Calculate sha256 of uncompressed serialization format of G, treat the
	// result as x-coordinate, find the first point on  curve with this x-coordinate
	// (which happens to exist on the curve)
	//
	// This generator point is copied from projects `secp256k1-zkp` and `rust-secp256k1-zkp` with respect, see :
	// https://github.com/ElementsProject/secp256k1-zkp/blob/master/src/modules/rangeproof/main_impl.h
	// https://github.com/mimblewimble/rust-secp256k1-zkp/blob/master/src/constants.rs
	Hx, _ = new(big.Int).SetString("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0", 16)
	Hy, _ = new(big.Int).SetString("31d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904", 16)
	G1    = &Point{theCurve.Params().Gx, theCurve.Params().Gy}
	G2    = &Point{Hx, Hy}
)
