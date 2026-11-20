// Does the SSH key exchange: picks algorithms, agrees on a secret and turns on encryption.

package sshprobe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SSH needs SHA-1 for older servers, we only use it to talk to them
	"crypto/sha256"
	"fmt"
	"hash"
	"math/big"
	"slices"
)

// The algorithms we speak, best first. Host key types are only listed so the
// server can pick one, we never check the signature.
var (
	ourKex      = []string{"curve25519-sha256", "curve25519-sha256@libssh.org", "diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1"}
	ourHostKeys = []string{"ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa", "ssh-dss"}
	ourCiphers  = []string{"aes128-ctr"}
	ourMACs     = []string{"hmac-sha2-256", "hmac-sha1"}
	ourComp     = []string{"none"}
)

// kexInit is a parsed KEXINIT message.
type kexInit struct {
	kex, hostKeys          []string
	ciphersC2S, ciphersS2C []string
	macsC2S, macsS2C       []string
	compC2S, compS2C       []string
}

func parseKexInit(p []byte) (*kexInit, error) {
	if len(p) == 0 || p[0] != msgKexInit {
		return nil, fmt.Errorf("expected the server's algorithm list, got message %d", firstByte(p))
	}
	r := reader{b: p[1:]}
	r.take(16) // random cookie
	k := &kexInit{
		kex:        r.nameList(),
		hostKeys:   r.nameList(),
		ciphersC2S: r.nameList(),
		ciphersS2C: r.nameList(),
		macsC2S:    r.nameList(),
		macsS2C:    r.nameList(),
		compC2S:    r.nameList(),
		compS2C:    r.nameList(),
	}
	r.nameList() // languages, both ways
	r.nameList()
	r.bool() // first_kex_packet_follows, servers don't use it
	r.uint32()
	if r.err != nil {
		return nil, fmt.Errorf("bad algorithm list: %w", r.err)
	}
	return k, nil
}

func firstByte(p []byte) byte {
	if len(p) == 0 {
		return 0
	}
	return p[0]
}

func ourKexInit() []byte {
	cookie := make([]byte, 16)
	_, _ = rand.Read(cookie)
	return newMsg(msgKexInit).raw(cookie).
		nameList(ourKex).nameList(ourHostKeys).
		nameList(ourCiphers).nameList(ourCiphers).
		nameList(ourMACs).nameList(ourMACs).
		nameList(ourComp).nameList(ourComp).
		nameList(nil).nameList(nil).
		bool(false).uint32(0).bytes()
}

// pick returns the first of ours that the server also has.
func pick(what string, ours, theirs []string) (string, error) {
	for _, a := range ours {
		if slices.Contains(theirs, a) {
			return a, nil
		}
	}
	return "", fmt.Errorf("no %s in common, server offers %v", what, theirs)
}

// keyExchange runs the whole exchange and switches both directions to the new keys.
func (c *conn) keyExchange() error {
	ic := ourKexInit()
	if err := c.writePacket(ic); err != nil {
		return err
	}
	is, err := c.expect(msgKexInit)
	if err != nil {
		return err
	}
	srv, err := parseKexInit(is)
	if err != nil {
		return err
	}

	kexAlg, err := pick("key exchange", ourKex, srv.kex)
	if err != nil {
		return err
	}
	if _, err := pick("host key type", ourHostKeys, srv.hostKeys); err != nil {
		return err
	}
	for _, l := range [][]string{srv.ciphersC2S, srv.ciphersS2C} {
		if _, err := pick("cipher", ourCiphers, l); err != nil {
			return err
		}
	}
	macC2S, err := pick("MAC", ourMACs, srv.macsC2S)
	if err != nil {
		return err
	}
	macS2C, err := pick("MAC", ourMACs, srv.macsS2C)
	if err != nil {
		return err
	}
	for _, l := range [][]string{srv.compC2S, srv.compS2C} {
		if _, err := pick("compression", ourComp, l); err != nil {
			return err
		}
	}

	newHash := sha256.New
	if kexAlg == "diffie-hellman-group14-sha1" {
		newHash = sha1.New
	}

	// Both sides hash everything said so far, so neither can be tricked.
	h := newHash()
	for _, s := range [][]byte{[]byte(clientBanner), []byte(c.serverBanner), ic, is} {
		h.Write(newMsg(0).blob(s).bytes()[1:])
	}

	var secret []byte
	if kexAlg == "diffie-hellman-group14-sha256" || kexAlg == "diffie-hellman-group14-sha1" {
		secret, err = c.dhGroup14(h)
	} else {
		secret, err = c.curve25519(h)
	}
	if err != nil {
		return err
	}
	k := appendMpint(nil, secret)
	h.Write(k)
	exchangeHash := h.Sum(nil)
	c.sessionID = exchangeHash

	if err := c.writePacket([]byte{msgNewKeys}); err != nil {
		return err
	}
	derive := func(letter byte, n int) []byte { return deriveKey(newHash, k, exchangeHash, c.sessionID, letter, n) }
	newMAC, size := macAlg(macC2S)
	c.out.setKeys(derive('A', 16), derive('C', 16), newMAC, derive('E', size))
	if _, err := c.expect(msgNewKeys); err != nil {
		return err
	}
	newMAC, size = macAlg(macS2C)
	c.in.setKeys(derive('B', 16), derive('D', 16), newMAC, derive('F', size))
	return nil
}

// curve25519 does the elliptic curve exchange (RFC 8731) and returns the shared secret.
func (c *conn) curve25519(h hash.Hash) ([]byte, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	qc := priv.PublicKey().Bytes()
	if err := c.writePacket(newMsg(msgKexInitDH).blob(qc).bytes()); err != nil {
		return nil, err
	}
	p, err := c.expect(msgKexReply)
	if err != nil {
		return nil, err
	}
	r := reader{b: p[1:]}
	hostKey, qs := r.blob(), r.blob()
	r.blob() // signature, not checked
	if r.err != nil {
		return nil, fmt.Errorf("bad key exchange reply: %w", r.err)
	}
	peer, err := ecdh.X25519().NewPublicKey(qs)
	if err != nil {
		return nil, fmt.Errorf("bad server key: %w", err)
	}
	secret, err := priv.ECDH(peer)
	if err != nil {
		return nil, err
	}
	for _, s := range [][]byte{hostKey, qc, qs} {
		h.Write(newMsg(0).blob(s).bytes()[1:])
	}
	return secret, nil
}

// group14 is the 2048-bit prime from RFC 3526, generator 2.
var group14, _ = new(big.Int).SetString(
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"+
		"020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"+
		"4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"+
		"98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"+
		"9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"+
		"3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)

// dhGroup14 does the classic Diffie-Hellman exchange (RFC 4253) and returns the shared secret.
func (c *conn) dhGroup14(h hash.Hash) ([]byte, error) {
	limit := new(big.Int).Sub(group14, big.NewInt(3))
	x, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	x.Add(x, big.NewInt(2))
	e := new(big.Int).Exp(big.NewInt(2), x, group14)
	if err := c.writePacket(newMsg(msgKexInitDH).mpint(e.Bytes()).bytes()); err != nil {
		return nil, err
	}
	p, err := c.expect(msgKexReply)
	if err != nil {
		return nil, err
	}
	r := reader{b: p[1:]}
	hostKey, fb := r.blob(), r.blob()
	r.blob() // signature, not checked
	if r.err != nil {
		return nil, fmt.Errorf("bad key exchange reply: %w", r.err)
	}
	f := new(big.Int).SetBytes(fb)
	if f.Cmp(big.NewInt(1)) <= 0 || f.Cmp(new(big.Int).Sub(group14, big.NewInt(1))) >= 0 {
		return nil, fmt.Errorf("bad server key")
	}
	h.Write(newMsg(0).blob(hostKey).bytes()[1:])
	h.Write(appendMpint(nil, e.Bytes()))
	h.Write(appendMpint(nil, f.Bytes()))
	return new(big.Int).Exp(f, x, group14).Bytes(), nil
}

// deriveKey makes n bytes of key material for one letter, as RFC 4253 section 7.2 says.
func deriveKey(newHash func() hash.Hash, k, exchangeHash, sessionID []byte, letter byte, n int) []byte {
	h := newHash()
	h.Write(k)
	h.Write(exchangeHash)
	h.Write([]byte{letter})
	h.Write(sessionID)
	out := h.Sum(nil)
	for len(out) < n {
		h := newHash()
		h.Write(k)
		h.Write(exchangeHash)
		h.Write(out)
		out = h.Sum(out)
	}
	return out[:n]
}

// macAlg returns the hash and key size for a MAC name we picked.
func macAlg(name string) (func() hash.Hash, int) {
	if name == "hmac-sha1" {
		return sha1.New, sha1.Size
	}
	return sha256.New, sha256.Size
}

// setKeys turns on aes128-ctr and the MAC for one direction.
func (d *direction) setKeys(iv, key []byte, mac func() hash.Hash, macKey []byte) {
	block, _ := aes.NewCipher(key) // key is always 16 bytes, so this can't fail
	d.stream = cipher.NewCTR(block, iv)
	d.blockSize = aes.BlockSize
	d.mac = mac
	d.macKey = macKey
}
