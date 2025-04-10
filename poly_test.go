package katecommitment_test

import (
	"testing"

	katecommitment "github.com/52funny/kate-commitment"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
)

func TestPolyDiv(t *testing.T) {
	// A(x) = -24 - 2x + 2x^2
	ax := []fr.Element{
		*new(fr.Element).SetInt64(-24),
		*new(fr.Element).SetInt64(-2),
		fr.NewElement(2),
	}

	// B(x) = 3 + x
	bx := []fr.Element{
		fr.NewElement(3),
		fr.NewElement(1),
	}

	// q(x) should be -8 + 2x
	qx, err := katecommitment.PolyDiv(ax, bx)
	assert.Nil(t, err)
	expected := []fr.Element{
		*new(fr.Element).SetInt64(-8),
		fr.NewElement(2),
	}
	for i, val := range qx {
		assert.Equal(t, expected[i].String(), val.String())
	}
}

func TestPolyDivAxZero(t *testing.T) {
	ax := []fr.Element{
		fr.NewElement(0),
		fr.NewElement(0),
	}
	bx := []fr.Element{
		fr.NewElement(3),
		fr.NewElement(1),
	}

	qx, err := katecommitment.PolyDiv(ax, bx)
	assert.Nil(t, err)
	assert.Equal(t, fr.NewElement(0), qx[0])
}
