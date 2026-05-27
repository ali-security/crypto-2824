// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientAuthRestrictedPublicKeyAlgos(t *testing.T) {
	for _, tt := range []struct {
		name      string
		key       Signer
		wantError bool
	}{
		{"rsa", testSigners["rsa"], false},
		{"dsa", testSigners["dsa"], true},
		{"ed25519", testSigners["ed25519"], true},
	} {
		c1, c2, err := netPipe()
		if err != nil {
			t.Fatalf("netPipe: %v", err)
		}
		defer c1.Close()
		defer c2.Close()
		serverConf := &ServerConfig{
			PublicKeyAuthAlgorithms: []string{KeyAlgoRSASHA256, KeyAlgoRSASHA512},
			PublicKeyCallback: func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
				return nil, nil
			},
		}
		serverConf.AddHostKey(testSigners["ecdsap256"])

		done := make(chan struct{})
		go func() {
			defer close(done)
			NewServerConn(c1, serverConf)
		}()

		clientConf := ClientConfig{
			User: "user",
			Auth: []AuthMethod{
				PublicKeys(tt.key),
			},
			HostKeyCallback: InsecureIgnoreHostKey(),
		}

		_, _, _, err = NewClientConn(c2, "", &clientConf)
		if err != nil {
			if !tt.wantError {
				t.Errorf("%s: got unexpected error %q", tt.name, err.Error())
			}
		} else if tt.wantError {
			t.Errorf("%s: succeeded, but want error", tt.name)
		}
		<-done
	}
}

func TestMaxAuthTriesNoneMethod(t *testing.T) {
	username := "testuser"
	serverConfig := &ServerConfig{
		MaxAuthTries: 2,
		PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
			if conn.User() == username && string(password) == clientPassword {
				return nil, nil
			}
			return nil, errors.New("invalid credentials")
		},
	}
	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	defer c1.Close()
	defer c2.Close()

	var serverAuthErrors []error

	serverConfig.AddHostKey(testSigners["rsa"])
	serverConfig.AuthLogCallback = func(conn ConnMetadata, method string, err error) {
		serverAuthErrors = append(serverAuthErrors, err)
	}
	go newServer(c1, serverConfig)

	clientConfig := ClientConfig{
		User:            username,
		HostKeyCallback: InsecureIgnoreHostKey(),
	}
	clientConfig.SetDefaults()
	// Our client will send 'none' auth only once, so we need to send the
	// requests manually.
	c := &connection{
		sshConn: sshConn{
			conn:          c2,
			user:          username,
			clientVersion: []byte(packageVersion),
		},
	}
	c.serverVersion, err = exchangeVersions(c.sshConn.conn, c.clientVersion)
	if err != nil {
		t.Fatalf("unable to exchange version: %v", err)
	}
	c.transport = newClientTransport(
		newTransport(c.sshConn.conn, clientConfig.Rand, true /* is client */),
		c.clientVersion, c.serverVersion, &clientConfig, "", c.sshConn.RemoteAddr())
	if err := c.transport.waitSession(); err != nil {
		t.Fatalf("unable to wait session: %v", err)
	}
	c.sessionID = c.transport.getSessionID()
	if err := c.transport.writePacket(Marshal(&serviceRequestMsg{serviceUserAuth})); err != nil {
		t.Fatalf("unable to send ssh-userauth message: %v", err)
	}
	packet, err := c.transport.readPacket()
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) > 0 && packet[0] == msgExtInfo {
		packet, err = c.transport.readPacket()
		if err != nil {
			t.Fatal(err)
		}
	}
	var serviceAccept serviceAcceptMsg
	if err := Unmarshal(packet, &serviceAccept); err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= serverConfig.MaxAuthTries; i++ {
		auth := new(noneAuth)
		_, _, err := auth.auth(c.sessionID, clientConfig.User, c.transport, clientConfig.Rand, nil)
		if i < serverConfig.MaxAuthTries {
			if err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err == nil {
			t.Fatal("client: got no error")
		} else if !strings.Contains(err.Error(), "too many authentication failures") {
			t.Fatalf("client: got unexpected error: %v", err)
		}
	}
	if len(serverAuthErrors) != 3 {
		t.Fatalf("unexpected number of server auth errors: %v, errors: %+v", len(serverAuthErrors), serverAuthErrors)
	}
	for _, err := range serverAuthErrors {
		if !errors.Is(err, ErrNoAuth) {
			t.Errorf("go error: %v; want: %v", err, ErrNoAuth)
		}
	}
}

func TestMaxAuthTriesFirstNoneAuthErrorIgnored(t *testing.T) {
	username := "testuser"
	serverConfig := &ServerConfig{
		MaxAuthTries: 1,
		PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
			if conn.User() == username && string(password) == clientPassword {
				return nil, nil
			}
			return nil, errors.New("invalid credentials")
		},
	}
	clientConfig := &ClientConfig{
		User: username,
		Auth: []AuthMethod{
			Password(clientPassword),
		},
		HostKeyCallback: InsecureIgnoreHostKey(),
	}

	serverAuthErrors, err := doClientServerAuth(t, serverConfig, clientConfig)
	if err != nil {
		t.Fatalf("client login error: %s", err)
	}
	if len(serverAuthErrors) != 2 {
		t.Fatalf("unexpected number of server auth errors: %v, errors: %+v", len(serverAuthErrors), serverAuthErrors)
	}
	if !errors.Is(serverAuthErrors[0], ErrNoAuth) {
		t.Errorf("go error: %v; want: %v", serverAuthErrors[0], ErrNoAuth)
	}
	if serverAuthErrors[1] != nil {
		t.Errorf("unexpected error: %v", serverAuthErrors[1])
	}
}

func TestNewServerConnValidationErrors(t *testing.T) {
	serverConf := &ServerConfig{
		PublicKeyAuthAlgorithms: []string{CertAlgoRSAv01},
	}
	c := &markerConn{}
	_, _, _, err := NewServerConn(c, serverConf)
	if err == nil {
		t.Fatal("NewServerConn with invalid public key auth algorithms succeeded")
	}
	if !c.isClosed() {
		t.Fatal("NewServerConn with invalid public key auth algorithms left connection open")
	}
	if c.isUsed() {
		t.Fatal("NewServerConn with invalid public key auth algorithms used connection")
	}

	serverConf = &ServerConfig{
		Config: Config{
			KeyExchanges: []string{kexAlgoDHGEXSHA256},
		},
	}
	c = &markerConn{}
	_, _, _, err = NewServerConn(c, serverConf)
	if err == nil {
		t.Fatal("NewServerConn with unsupported key exchange succeeded")
	}
	if !c.isClosed() {
		t.Fatal("NewServerConn with unsupported key exchange left connection open")
	}
	if c.isUsed() {
		t.Fatal("NewServerConn with unsupported key exchange used connection")
	}
}

func TestBannerError(t *testing.T) {
	serverConfig := &ServerConfig{
		BannerCallback: func(ConnMetadata) string {
			return "banner from BannerCallback"
		},
		NoClientAuth: true,
		NoClientAuthCallback: func(ConnMetadata) (*Permissions, error) {
			err := &BannerError{
				Err:     errors.New("error from NoClientAuthCallback"),
				Message: "banner from NoClientAuthCallback",
			}
			return nil, fmt.Errorf("wrapped: %w", err)
		},
		PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
			return &Permissions{}, nil
		},
		PublicKeyCallback: func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
			return nil, &BannerError{
				Err:     errors.New("error from PublicKeyCallback"),
				Message: "banner from PublicKeyCallback",
			}
		},
		KeyboardInteractiveCallback: func(conn ConnMetadata, client KeyboardInteractiveChallenge) (*Permissions, error) {
			return nil, &BannerError{
				Err:     nil, // make sure that a nil inner error is allowed
				Message: "banner from KeyboardInteractiveCallback",
			}
		},
	}
	serverConfig.AddHostKey(testSigners["rsa"])

	var banners []string
	clientConfig := &ClientConfig{
		User: "test",
		Auth: []AuthMethod{
			PublicKeys(testSigners["rsa"]),
			KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
				return []string{"letmein"}, nil
			}),
			Password(clientPassword),
		},
		HostKeyCallback: InsecureIgnoreHostKey(),
		BannerCallback: func(msg string) error {
			banners = append(banners, msg)
			return nil
		},
	}

	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	defer c1.Close()
	defer c2.Close()
	go newServer(c1, serverConfig)
	c, _, _, err := NewClientConn(c2, "", clientConfig)
	if err != nil {
		t.Fatalf("client connection failed: %v", err)
	}
	defer c.Close()

	wantBanners := []string{
		"banner from BannerCallback",
		"banner from NoClientAuthCallback",
		"banner from PublicKeyCallback",
		"banner from KeyboardInteractiveCallback",
	}
	if !reflect.DeepEqual(banners, wantBanners) {
		t.Errorf("got banners:\n%q\nwant banners:\n%q", banners, wantBanners)
	}
}

func TestPartialSuccessWithNonNilPerms(t *testing.T) {
	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	defer c1.Close()
	defer c2.Close()

	serverConf := &ServerConfig{
		PublicKeyCallback: func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
			if bytes.Equal(key.Marshal(), testPublicKeys["rsa"].Marshal()) {
				// Intentionally return non-nil Permissions along with a
				// PartialSuccessError. Since permissions are reset between
				// authentication steps, this constitutes invalid library usage
				// and the server is expected to reject the connection.
				return &Permissions{Extensions: map[string]string{"permit-port-forwarding": ""}}, &PartialSuccessError{
					Next: ServerAuthCallbacks{
						PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
							if string(password) == clientPassword {
								return nil, nil
							}
							return nil, nil
						},
					},
				}
			}
			return nil, errors.New("invalid credentials")
		},
	}
	serverConf.AddHostKey(testSigners["rsa"])

	clientConf := ClientConfig{
		User: "user",
		Auth: []AuthMethod{
			PublicKeys(testSigners["rsa"]),
			Password(clientPassword),
		},
		HostKeyCallback: InsecureIgnoreHostKey(),
	}

	go NewServerConn(c1, serverConf)

	_, _, _, err = NewClientConn(c2, "", &clientConf)
	if err == nil {
		t.Fatal("authentication succeeded unexpectedly; server should have rejected non-nil Permissions combined with PartialSuccessError")
	}
}

func TestPublicKeyCallbackLastSeen(t *testing.T) {
	var lastSeenKey PublicKey

	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	defer c1.Close()
	defer c2.Close()
	serverConf := &ServerConfig{
		PublicKeyCallback: func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
			lastSeenKey = key
			fmt.Printf("seen %#v\n", key)
			if _, ok := key.(*dsaPublicKey); !ok {
				return nil, errors.New("nope")
			}
			return nil, nil
		},
	}
	serverConf.AddHostKey(testSigners["ecdsap256"])

	done := make(chan struct{})
	go func() {
		defer close(done)
		NewServerConn(c1, serverConf)
	}()

	clientConf := ClientConfig{
		User: "user",
		Auth: []AuthMethod{
			PublicKeys(testSigners["rsa"], testSigners["dsa"], testSigners["ed25519"]),
		},
		HostKeyCallback: InsecureIgnoreHostKey(),
	}

	_, _, _, err = NewClientConn(c2, "", &clientConf)
	if err != nil {
		t.Fatal(err)
	}
	<-done

	expectedPublicKey := testSigners["dsa"].PublicKey().Marshal()
	lastSeenMarshalled := lastSeenKey.Marshal()
	if !bytes.Equal(lastSeenMarshalled, expectedPublicKey) {
		t.Errorf("unexpected key: got %#v, want %#v", lastSeenKey, testSigners["dsa"].PublicKey())
	}
}

type markerConn struct {
	closed uint32
	used   uint32
}

func (c *markerConn) isClosed() bool {
	return atomic.LoadUint32(&c.closed) != 0
}

func (c *markerConn) isUsed() bool {
	return atomic.LoadUint32(&c.used) != 0
}

func (c *markerConn) Close() error {
	atomic.StoreUint32(&c.closed, 1)
	return nil
}

func (c *markerConn) Read(b []byte) (n int, err error) {
	atomic.StoreUint32(&c.used, 1)
	if atomic.LoadUint32(&c.closed) != 0 {
		return 0, net.ErrClosed
	} else {
		return 0, io.EOF
	}
}

func (c *markerConn) Write(b []byte) (n int, err error) {
	atomic.StoreUint32(&c.used, 1)
	if atomic.LoadUint32(&c.closed) != 0 {
		return 0, net.ErrClosed
	} else {
		return 0, io.ErrClosedPipe
	}
}

func (*markerConn) LocalAddr() net.Addr  { return nil }
func (*markerConn) RemoteAddr() net.Addr { return nil }

func (*markerConn) SetDeadline(t time.Time) error      { return nil }
func (*markerConn) SetReadDeadline(t time.Time) error  { return nil }
func (*markerConn) SetWriteDeadline(t time.Time) error { return nil }

// TestServerAuthSourceAddressCriticalOption is the v0.30.0 analog of the
// upstream CVE-2026-46595 regression test. Upstream exercises the bypass via
// VerifiedPublicKeyCallback, which does not exist in this release; here a
// non-publickey callback (PasswordCallback) returns Permissions carrying a
// mismatching source-address critical option. Before the fix the restriction
// was only validated in the publickey path and was silently skipped, so the
// client would log in. After the fix the option is enforced on the resolved
// permissions regardless of the authenticating method and the login fails.
func TestServerAuthSourceAddressCriticalOption(t *testing.T) {
	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	defer c1.Close()
	defer c2.Close()

	serverConf := &ServerConfig{
		PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
			return &Permissions{
				CriticalOptions: map[string]string{
					sourceAddressCriticalOption: "192.168.99.99",
				},
			}, nil
		},
	}
	serverConf.AddHostKey(testSigners["rsa"])

	clientConf := ClientConfig{
		User: "user",
		Auth: []AuthMethod{
			Password("password"),
		},
		HostKeyCallback: InsecureIgnoreHostKey(),
	}

	go NewServerConn(c1, serverConf)

	_, _, _, err = NewClientConn(c2, "", &clientConf)
	if err == nil {
		t.Fatal("client login succeeded despite a mismatching source-address critical option")
	}
}

// skTestSigner is a Signer that produces SK-ECDSA signatures over
// user-auth data, simulating a FIDO/U2F authenticator. The flags
// byte (UP and other bits) is caller-controlled so tests can exercise
// the server's user-presence enforcement and its opt-out paths. This
// is test-only: the real Signer is hardware-backed.
type skTestSigner struct {
	priv        *ecdsa.PrivateKey
	pub         PublicKey
	flags       byte
	application string
}

func (s *skTestSigner) PublicKey() PublicKey { return s.pub }

func (s *skTestSigner) Sign(r io.Reader, data []byte) (*Signature, error) {
	h := sha256.New()
	h.Write([]byte(s.application))
	appDigest := h.Sum(nil)
	h.Reset()
	h.Write(data)
	dataDigest := h.Sum(nil)
	var counter uint32 = 1
	blob := struct {
		ApplicationDigest []byte `ssh:"rest"`
		Flags             byte
		Counter           uint32
		MessageDigest     []byte `ssh:"rest"`
	}{appDigest, s.flags, counter, dataDigest}
	h.Reset()
	h.Write(Marshal(blob))
	digest := h.Sum(nil)
	x, y, err := ecdsa.Sign(r, s.priv, digest)
	if err != nil {
		return nil, err
	}
	return &Signature{
		Format: KeyAlgoSKECDSA256,
		Blob:   Marshal(struct{ R, S *big.Int }{x, y}),
		Rest: Marshal(struct {
			Flags   byte
			Counter uint32
		}{s.flags, counter}),
	}, nil
}

// TestServerAuthSKUserPresence drives the full userAuthLoop with an SK
// public-key client and verifies the server's wiring of the UP check
// and its two opt-out paths: the per-key Permissions.Extensions route
// and (via cert) the cert-level route. It also confirms that non-SK
// clients are unaffected by the new code path.
func TestServerAuthSKUserPresence(t *testing.T) {
	userKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	skPub := &skECDSAPublicKey{application: "ssh:", PublicKey: userKey.PublicKey}

	runAuth := func(t *testing.T, signer Signer, perms *Permissions) error {
		t.Helper()
		c1, c2, err := netPipe()
		if err != nil {
			t.Fatal(err)
		}
		defer c1.Close()
		defer c2.Close()

		serverConf := &ServerConfig{
			PublicKeyCallback: func(ConnMetadata, PublicKey) (*Permissions, error) {
				return perms, nil
			},
		}
		serverConf.AddHostKey(testSigners["ecdsa"])

		serverErr := make(chan error, 1)
		go func() {
			_, _, _, err := NewServerConn(c1, serverConf)
			serverErr <- err
		}()

		clientConf := &ClientConfig{
			User:            "user",
			Auth:            []AuthMethod{PublicKeys(signer)},
			HostKeyCallback: InsecureIgnoreHostKey(),
		}
		_, _, _, clientErr := NewClientConn(c2, "", clientConf)
		<-serverErr
		return clientErr
	}

	optOut := &Permissions{Extensions: map[string]string{noTouchRequiredExtension: ""}}

	t.Run("UP=1, default perms accepts", func(t *testing.T) {
		s := &skTestSigner{priv: userKey, pub: skPub, flags: flagUserPresence, application: "ssh:"}
		if err := runAuth(t, s, nil); err != nil {
			t.Errorf("expected auth to succeed: %v", err)
		}
	})
	t.Run("UP=0, default perms rejects", func(t *testing.T) {
		s := &skTestSigner{priv: userKey, pub: skPub, flags: 0, application: "ssh:"}
		if err := runAuth(t, s, nil); err == nil {
			t.Error("expected auth to fail with UP=0")
		}
	})
	t.Run("UP=0, perms opt-out accepts", func(t *testing.T) {
		s := &skTestSigner{priv: userKey, pub: skPub, flags: 0, application: "ssh:"}
		if err := runAuth(t, s, optOut); err != nil {
			t.Errorf("expected auth to succeed with opt-out: %v", err)
		}
	})
	t.Run("UP=0, perms CriticalOptions does NOT opt out", func(t *testing.T) {
		s := &skTestSigner{priv: userKey, pub: skPub, flags: 0, application: "ssh:"}
		critOnly := &Permissions{CriticalOptions: map[string]string{noTouchRequiredExtension: ""}}
		if err := runAuth(t, s, critOnly); err == nil {
			t.Error("no-touch-required in CriticalOptions must not waive UP")
		}
	})
	t.Run("non-SK RSA signer unaffected", func(t *testing.T) {
		if err := runAuth(t, testSigners["rsa"], nil); err != nil {
			t.Errorf("plain RSA auth must still work: %v", err)
		}
	})
}
