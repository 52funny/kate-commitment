package katecommitment_test

import (
	"testing"

	katecommitment "github.com/52funny/kate-commitment"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
)

func TestSetup(t *testing.T) {
	pp := katecommitment.Setup(10)
	assert.Equal(t, 11, len(pp.GetG()))
}

func TestVerify(t *testing.T) {
	pp := katecommitment.Setup(10)

	// random coefficients
	coeffs := make([]fr.Element, 3)
	for i := range coeffs {
		coeffs[i].SetRandom()
	}

	x0 := *new(fr.Element).SetInt64(-3)
	y0 := katecommitment.ComputePolynomial(coeffs, x0)

	c, err := katecommitment.CommitPolynomial(&pp, coeffs)
	assert.NoError(t, err)

	w, err := katecommitment.CreateWitness(&pp, coeffs, x0, y0)
	assert.NoError(t, err)

	res, err := katecommitment.Verify(&pp, c, w, x0, y0)
	assert.NoError(t, err)

	assert.True(t, res)
}
