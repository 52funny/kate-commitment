package katecommitment_test

import (
	"testing"

	katecommitment "github.com/52funny/kate-commitment"
	"github.com/go-playground/assert/v2"
)

func TestSetup(t *testing.T) {
	pp := katecommitment.Setup(10)
	assert.Equal(t, 11, len(pp.GetG()))
}
