package blackmail

import (
	"testing"
)

func TestSign(t *testing.T) {
	pub, priv, err := SignKeys("./testdata/test.pub", "./testdata/test.priv")
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("Hello\n")
	sig, err := signMessage(msg, pub, priv)
	if err != nil {
		t.Fatal(err)
	}

	_ = sig

	//fmt.Print(string(msg))
	//fmt.Print(string(sig))
}
