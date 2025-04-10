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
	gJac    []*bls12381.G1Jac
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

	gJac := make([]*bls12381.G1Jac, 0, t+1)

	gAffine := make([]*bls12381.G1Affine, 0, t+1)

	tmp := fr.One()

	for range t + 1 {
		gExp := new(bls12381.G1Jac).ScalarMultiplicationBase(tmp.BigInt(new(big.Int)))
		gJac = append(gJac, gExp)

		gAffine = append(gAffine, new(bls12381.G1Affine).FromJacobian(gExp))

		// tmp self multiply by alpha
		// 1, alpha, alpha^2, ..., alpha^t
		tmp.Mul(&tmp, alpha)
	}

	pp := PublicParameters{
		t:       t,
		gAffine: gAffine,
		gJac:    gJac,
	}
	return pp
}
