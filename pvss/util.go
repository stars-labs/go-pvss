/*
 * Copyright (c) 2021 Stars-labs.
 * Author: darlzan@foxmail.com
 *
 * Code is licensed under GPLv3.0 License. You should have received a copy of the GNU General Public License v3.0
 * along with the go-pvss library. If not, see <http://www.gnu.org/licenses/>.
 */

package pvss

import (
	"hash"
	"math/big"
)

func Hash(hasher hash.Hash, values ...*big.Int) []byte {
	hasher.Reset()
	for _, x := range values {
		hasher.Write(x.Bytes())
	}
	return hasher.Sum(nil)
}

// HashMod will calculate the hash of given values using the given `hasher`,
// and then take the result as big.Int and mod n.
func HashMod(n *big.Int, hasher hash.Hash, values ...*big.Int) *big.Int {
	hash256 := Hash(hasher, values...)
	h := new(big.Int).SetBytes(hash256)
	h.Mod(h, n)
	return h
}
