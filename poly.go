package katecommitment

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// PolyDiv divides two polynomials A(x) and B(x).
// A(x) must exactly divide B(x).
// Notice: A(x) will be modified.
func PolyDiv(ax []fr.Element, bx []fr.Element) ([]fr.Element, error) {
	if len(bx) == 0 {
		return nil, fmt.Errorf("polynomial B cannot be empty")
	}
	if len(ax) < len(bx) {
		return nil, fmt.Errorf("degree of A must be greater than or equal to degree of B")
	}

	if PolyIsZero(bx) {
		return nil, fmt.Errorf("cannot divide by zero polynomial")
	}

	aPos := len(ax) - 1
	bPos := len(bx) - 1

	diff := aPos - bPos

	// out represents the quotient
	out := make([]fr.Element, diff+1)

	for diff >= 0 {
		quot := &out[diff]

		// quot = a_pos * b_pox
		quot.Mul(&ax[aPos], new(fr.Element).Inverse(&bx[bPos]))

		for i := bPos; i >= 0; i-- {
			prod := new(fr.Element).Mul(quot, &bx[i])
			sub := new(fr.Element).Sub(&ax[diff+i], prod)
			ax[diff+i].Set(sub)
		}
		// move the position of the polynomial A
		aPos--
		// move the next position of the polynomial difference
		diff--
	}
	return out, nil
}

// Return true if all the coefficients of the polynomial are zero.
// Otherwise return false.
func PolyIsZero(p []fr.Element) bool {
	for _, v := range p {
		if !v.IsZero() {
			return false
		}
	}
	return true
}
