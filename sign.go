// +build !blackmail_no_sign

// TODO: look at https://github.com/ProtonMail/gopenpgp
// Also: https://github.com/ProtonMail/crypto/commits/master/openpgp

package blackmail

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

// SignKeys loads the public and private keys from the
func SignKeys(pubFile, privFile string) (pub, priv []byte, err error) {
	pub, err = os.ReadFile(pubFile)
	if err != nil {
		return nil, nil, fmt.Errorf("blackmail.SignKeys: %w", err)
	}
	priv, err = os.ReadFile(privFile)
	if err != nil {
		return nil, nil, fmt.Errorf("blackmail.SignKeys: %w", err)
	}
	return pub, priv, nil
}

// SignCreateKeys creates a new signing key.
//
// $ gpg2 --no-default-keyring --keyring /tmp/test.gpg --batch --passphrase '' --quick-gen-key 'martin@arp242.net'
// gpg: keybox '/tmp/test.gpg' created
// gpg: key 6B4ED72ADCA0189C marked as ultimately trusted
// gpg: revocation certificate stored as '/home/martin/.config/gnupg/openpgp-revocs.d/B0D7F5E12D2E1FBB7F20CB256B4ED72ADCA0189C.rev'
//
// $ gpg2 -a --no-default-keyring --keyring /tmp/test.gpg --export 6B4ED72ADCA0189C > test.pub
// $ gpg2 -a --no-default-keyring --keyring /tmp/test.gpg --export-secret-keys B0D7F5E12D2E1FBB7F20CB256B4ED72ADCA0189C > test.priv
//
// $ gpg2 -a --no-keyring --detach-sign
// $ gpg2 -a --no-default-keyring --keyring /tmp/test.gpg --detach-sign < signed >! signature
//
// $ gpg2 --no-default-keyring --keyring /tmp/test.gpg --verify ./signature ./signed
// gpg: Signature made Tue 26 May 2020 19:06:03 WITA
// gpg:                using RSA key B0D7F5E12D2E1FBB7F20CB256B4ED72ADCA0189C
// gpg: Good signature from "martin@arp242.net" [ultimate]
//
//
// gpg: Signature made Tue 26 May 2020 19:09:50 WITA
// gpg:                using RSA key 6B4ED72ADCA0189C
// gpg: BAD signature from "martin@arp242.net" [ultimate]
//
// public is gpg export w/p --armor
// $ gpg2 --no-default-keyring --keyring ./public --verify ./signature ./signed
//
// https://gist.github.com/eliquious/9e96017f47d9bd43cdf9
// https://github.com/jchavannes/go-pgp
func SignCreateKeys() ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("blackmail.SignCreateKeys: %w", err)
	}

	n := time.Now().UTC()
	pub := new(bytes.Buffer)
	{
		pubKey := packet.NewECDSAPublicKey(n, &key.PublicKey)

		buf := new(bytes.Buffer)
		err = pubKey.Serialize(buf)
		if err != nil {
			return nil, nil, err
		}

		w, err := armor.Encode(pub, "PGP PUBLIC KEY BLOCK", nil)
		if err != nil {
			return nil, nil, err
		}
		_, err = w.Write(buf.Bytes())
		if err != nil {
			return nil, nil, err
		}
		w.Close()
	}
	priv := new(bytes.Buffer)
	{
		privKey := packet.NewECDSAPrivateKey(n, key)
		buf := new(bytes.Buffer)
		err = privKey.Serialize(buf)
		if err != nil {
			return nil, nil, err
		}

		w, err := armor.Encode(priv, "PGP PRIVATE KEY BLOCK", nil)
		if err != nil {
			return nil, nil, err
		}
		_, err = w.Write(buf.Bytes())
		if err != nil {
			return nil, nil, err
		}
		w.Close()
	}
	return pub.Bytes(), priv.Bytes(), nil
}

// TODO: add support for sending the public key; rfc3156:
//
// 7.  Distribution of OpenPGP public keys
//
//    Content-Type: application/pgp-keys
//    Required parameters: none
//    Optional parameters: none
//
//    A MIME body part of the content type "application/pgp-keys" contains
//    ASCII-armored transferable Public Key Packets as defined in [1],
//    section 10.1.

func signMessage(msg, pubKey, privKey []byte) ([]byte, error) {
	// Less confusing messages.
	if len(pubKey) == 0 {
		return nil, errors.New("signMessage: empty public key")
	}
	if len(privKey) == 0 {
		return nil, errors.New("signMessage: empty private key")
	}

	// TODO: better error when reversing pub/priv key.

	publicKeyPacket, err := getPublicKeyPacket(pubKey)
	if err != nil {
		return nil, fmt.Errorf("getPublicKeyPacket: %w", err)
	}

	privateKeyPacket, err := getPrivateKeyPacket(privKey)
	if err != nil {
		return nil, fmt.Errorf("getPrivateKeyPacket: %w", err)
	}

	entity, err := createEntity(publicKeyPacket, privateKeyPacket)
	if err != nil {
		return nil, fmt.Errorf("createEntity: %w", err)
	}

	writer := &bytes.Buffer{}
	err = openpgp.ArmoredDetachSign(writer, entity, bytes.NewReader(msg), nil)
	if err != nil {
		return nil, fmt.Errorf("blackmail.Sign: %w", err)
	}

	return bytes.ReplaceAll(writer.Bytes(), []byte("\n"), []byte("\r\n")), nil
}

// From https://gist.github.com/eliquious/9e96017f47d9bd43cdf9
func createEntity(pubKey *packet.PublicKey, privKey *packet.PrivateKey) (*openpgp.Entity, error) {
	config := packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		CompressionConfig: &packet.CompressionConfig{
			Level: 9,
		},
		RSABits: 4096,
	}
	currentTime := config.Now()
	uid := packet.NewUserId("", "", "")

	e := openpgp.Entity{
		PrimaryKey: pubKey,
		PrivateKey: privKey,
		Identities: make(map[string]*openpgp.Identity),
	}
	isPrimaryID := false

	e.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Name,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime: currentTime,
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   packet.PubKeyAlgoRSA,
			Hash:         config.Hash(),
			IsPrimaryId:  &isPrimaryID,
			FlagsValid:   true,
			FlagSign:     true,
			FlagCertify:  true,
			IssuerKeyId:  &e.PrimaryKey.KeyId,
		},
	}

	keyLifetimeSecs := uint32(86400 * 365)

	e.Subkeys = make([]openpgp.Subkey, 1)
	e.Subkeys[0] = openpgp.Subkey{
		PublicKey:  pubKey,
		PrivateKey: privKey,
		Sig: &packet.Signature{
			CreationTime:              currentTime,
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                packet.PubKeyAlgoRSA,
			Hash:                      config.Hash(),
			PreferredHash:             []uint8{8}, // SHA-256
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &e.PrimaryKey.KeyId,
			KeyLifetimeSecs:           &keyLifetimeSecs,
		},
	}
	return &e, nil
}

func getPublicKeyPacket(k []byte) (*packet.PublicKey, error) {
	pkt, err := getPacket(openpgp.PublicKeyType, k)
	if err != nil {
		return nil, fmt.Errorf("getPacket: %w", err)
	}

	key, ok := pkt.(*packet.PublicKey)
	if !ok {
		return nil, fmt.Errorf("could not assert %T to *packet.PublicKey", pkt)
	}
	return key, nil
}

func getPrivateKeyPacket(k []byte) (*packet.PrivateKey, error) {
	pkt, err := getPacket(openpgp.PrivateKeyType, k)
	if err != nil {
		return nil, fmt.Errorf("getPacket: %w", err)
	}

	key, ok := pkt.(*packet.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("could not assert %T to *packet.PrivateKey", pkt)
	}
	return key, nil
}

func getPacket(keyType string, k []byte) (packet.Packet, error) {
	block, err := armor.Decode(bytes.NewReader(k))
	if err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("armor.Decode: could not find armored PGP key block")
		}
		return nil, fmt.Errorf("armor.Decode: %w", err)
	}

	if block.Type != keyType {
		return nil, fmt.Errorf("%T is not %s", block.Type, keyType)
	}

	r := packet.NewReader(block.Body)
	pkt, err := r.Next()
	if err != nil {
		return nil, fmt.Errorf("r.Next: %w", err)
	}
	return pkt, nil
}
