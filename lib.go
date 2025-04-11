package katecommitment

import (
	"fmt"
	"math/big"
	"strings"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// PublicParameters contains the public parameters.
// g, g^\alpha, g^{\alpha^2}, ..., g^{\alpha^{t}} are the generators of G1.
// h, h^\alpha, h^{\alpha^2}, ..., h^{\alpha^{t}} are the generators of G2.
type PublicParameters struct {
	t       int
	gAffine []*bls12381.G1Affine
	hAffine []*bls12381.G2Affine
}

// Return all the public parameters in G1.
func (pp *PublicParameters) GetG() []*bls12381.G1Affine {
	return pp.gAffine
}

func (pp *PublicParameters) String() string {
	s := new(strings.Builder)
	s.WriteString("[ ")
	for _, val := range pp.gAffine {
		s.WriteString(val.String())
		s.WriteString(", ")
	}
	s.WriteString("]")
	return s.String()
}

// Setup algorithm generates the public parameters.
func Setup(t int) PublicParameters {
	// set alpha to a 256 bit random number
	alpha := new(fr.Element)
	alpha.SetRandom()

	gAffine := make([]*bls12381.G1Affine, 0, t+1)
	hAffine := make([]*bls12381.G2Affine, 0, t+1)

	tmp := fr.One()

	for range t + 1 {
		gExp := new(bls12381.G1Jac).ScalarMultiplicationBase(tmp.BigInt(new(big.Int)))
		hExp := new(bls12381.G2Jac).ScalarMultiplicationBase(tmp.BigInt(new(big.Int)))

		gAffine = append(gAffine, new(bls12381.G1Affine).FromJacobian(gExp))
		hAffine = append(hAffine, new(bls12381.G2Affine).FromJacobian(hExp))

		// tmp self multiply by alpha
		// 1, alpha, alpha^2, ..., alpha^t
		tmp.Mul(&tmp, alpha)
	}

	pp := PublicParameters{
		t:       t,
		gAffine: gAffine,
		hAffine: hAffine,
	}
	return pp
}

// CommitPolynomial computes the commitment to a polynomial f(x) = a_0 + a_1 * x + ... + a_t * x^t.
// It's return the commitment c = g^{a_0} * g^{\alpha a_1} * g^{\alpha^2 a_2} * ... * g^{\alpha^t a_t}.
func CommitPolynomial(pp *PublicParameters, coeffs []fr.Element) (*bls12381.G1Affine, error) {
	if len(coeffs) > pp.t+1 {
		return nil, fmt.Errorf("coefficients length must less or equal t+1")
	}

	// c = \prod_{i=0}^t (g^{\alpha^i}) ^ {coeffs[i]}
	c := new(bls12381.G1Affine).SetInfinity()

	for i, val := range coeffs {
		parts := new(bls12381.G1Affine).ScalarMultiplication(pp.gAffine[i], val.BigInt(new(big.Int)))
		c.Add(c, parts)
	}
	return c, nil
}

// CreateWitness computes the witness at the polynomial q(x).
func CreateWitness(pp *PublicParameters, coeffs []fr.Element, x0 fr.Element, y0 fr.Element) (*bls12381.G1Affine, error) {
	if len(coeffs) > pp.t+1 {
		return nil, fmt.Errorf("coefficients length must less or equal t+1")
	}

	coeffsCopy := make([]fr.Element, len(coeffs))
	copy(coeffsCopy, coeffs)

	// f(x) - y
	coeffsCopy[0].Sub(&coeffsCopy[0], &y0)

	// B(x) = x - y
	bx := []fr.Element{
		*new(fr.Element).Neg(&x0),
		fr.One(),
	}

	// q(x) = (f(x) - y) / (x - x0)
	qx, err := PolyDiv(coeffsCopy, bx)
	if err != nil {
		return nil, err
	}

	// c = \prod_{i=0}^t (g^{\alpha^i}) ^ {qx[i]}
	c := new(bls12381.G1Affine).SetInfinity()
	for i, val := range qx {
		parts := new(bls12381.G1Affine).ScalarMultiplication(pp.gAffine[i], val.BigInt(new(big.Int)))
		c.Add(c, parts)
	}
	return c, nil
}

// Verify algorithm verifies the witness.
func Verify(pp *PublicParameters, c *bls12381.G1Affine, witness *bls12381.G1Affine, x0 fr.Element, y0 fr.Element) (bool, error) {
	_, _, g, h := bls12381.Generators()

	gNegy := new(bls12381.G1Affine).ScalarMultiplication(&g, y0.BigInt(new(big.Int)))

	cMinusgNegy := new(bls12381.G1Affine).Sub(c, gNegy)

	left, err := bls12381.Pair([]bls12381.G1Affine{*cMinusgNegy}, []bls12381.G2Affine{h})
	if err != nil {
		return false, err
	}

	// h^x0
	hX0 := new(bls12381.G2Affine).ScalarMultiplication(&h, x0.BigInt(new(big.Int)))
	tmp := new(bls12381.G2Affine).Sub(pp.hAffine[1], hX0)

	right, err := bls12381.Pair([]bls12381.G1Affine{*witness}, []bls12381.G2Affine{*tmp})
	if err != nil {
		return false, err
	}

	return left.Equal(&right), nil
}

// Calculate the polynomial f(x) value at x.
func ComputePolynomial(coeffs []fr.Element, x fr.Element) fr.Element {
	if len(coeffs) == 0 {
		return fr.NewElement(0)
	}
	xCopy := fr.Element{}
	xCopy.Set(&x)
	res := new(fr.Element).Set(&coeffs[0])
	for i := 1; i < len(coeffs); i++ {
		tmp := new(fr.Element).Mul(&xCopy, &coeffs[i])
		res.Add(res, tmp)
		xCopy.Mul(&xCopy, &x)
	}
	return *res
}
