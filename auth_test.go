package socks5

import (
	"bytes"
	"testing"
)

func TestNoAuth(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{1, NoAuth})
	conn := MockConn{}

	s, _ := New(&Config{})
	ctx, err := s.authenticate(&conn, req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if ctx.Method != NoAuth {
		t.Fatal("Invalid Context Method")
	}

	out := conn.buf.Bytes()
	if !bytes.Equal(out, []byte{socks5Version, NoAuth}) {
		t.Fatalf("bad: %v", out)
	}
}

func TestPasswordAuth_Valid(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{2, NoAuth, UserPassAuth})
	req.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	conn := MockConn{}

	cred := StaticCredentials{
		"foo": "bar",
	}

	cator := UserPassAuthenticator{Credentials: cred}

	s, _ := New(&Config{AuthMethods: []Authenticator{cator}})

	ctx, err := s.authenticate(&conn, req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if ctx.Method != UserPassAuth {
		t.Fatal("Invalid Context Method")
	}

	val, ok := ctx.Payload["Username"]
	if !ok {
		t.Fatal("Missing key Username in auth context's payload")
	}

	if val != "foo" {
		t.Fatal("Invalid Username in auth context's payload")
	}

	out := conn.buf.Bytes()
	if !bytes.Equal(out, []byte{socks5Version, UserPassAuth, 1, authSuccess}) {
		t.Fatalf("bad: %v", out)
	}
}

func TestPasswordAuth_Invalid(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{2, NoAuth, UserPassAuth})
	req.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'z'})
	conn := MockConn{}

	cred := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: cred}
	s, _ := New(&Config{AuthMethods: []Authenticator{cator}})

	ctx, err := s.authenticate(&conn, req)
	if err != UserAuthFailed {
		t.Fatalf("err: %v", err)
	}

	if ctx != nil {
		t.Fatal("Invalid Context Method")
	}

	out := conn.buf.Bytes()
	if !bytes.Equal(out, []byte{socks5Version, UserPassAuth, 1, authFailure}) {
		t.Fatalf("bad: %v", out)
	}
}

func TestNoSupportedAuth(t *testing.T) {
	req := bytes.NewBuffer(nil)
	req.Write([]byte{1, NoAuth})
	conn := MockConn{}

	cred := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: cred}

	s, _ := New(&Config{AuthMethods: []Authenticator{cator}})

	ctx, err := s.authenticate(&conn, req)
	if err != NoSupportedAuth {
		t.Fatalf("err: %v", err)
	}

	if ctx != nil {
		t.Fatal("Invalid Context Method")
	}

	out := conn.buf.Bytes()
	if !bytes.Equal(out, []byte{socks5Version, noAcceptable}) {
		t.Fatalf("bad: %v", out)
	}
}
