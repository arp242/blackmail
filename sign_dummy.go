// +build blackmail_no_sign

package blackmail

// Provide dummy Sign* implementations so you can opt to not depend on
// golang.org/x/crypto.

func SignKeys(pubFile, privFile string) (pub, priv []byte, err error) { return nil, nil, nil }
func SignCreateKeys() ([]byte, []byte, error)                         { return nil, nil, nil }
func signMessage(msg, pubKey, privKey []byte) ([]byte, error)         { return nil, nil }
