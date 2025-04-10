package katecommitment_test

import (
	"testing"

	katecommitment "github.com/52funny/kate-commitment"
	"github.com/stretchr/testify/assert"
)

func TestSetup(t *testing.T) {
	pp := katecommitment.Setup(10)
	assert.Equal(t, 11, len(pp.GetG()))
}
