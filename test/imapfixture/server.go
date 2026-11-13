// Package imapfixture supplies an isolated TLS server for focused Mail checks.
// It records command names only and never logs authentication material.
package imapfixture

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type Server struct {
	internalDates             map[string]string
	validity                  uint32
	uids                      []uint32
	flagged                   bool
	Host                      string
	Port                      int
	CertFile, KeyFile, CAFile string
	Roots                     *x509.CertPool
	listener                  net.Listener
	cancel                    context.CancelFunc
	mu                        sync.Mutex
	conns                     map[net.Conn]bool
	commands                  []string
	wg                        sync.WaitGroup
}

// mode is login, plain, continuation, oversized or stall.
func New(t *testing.T, mode string, users map[string]string) *Server {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated Mail fixture"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{validity: 77, uids: []uint32{101, 102}, Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, listener: listener, cancel: cancel, conns: map[net.Conn]bool{}, Roots: x509.NewCertPool()}
	s.Roots.AppendCertsFromPEM(certPEM)
	dir := t.TempDir()
	s.CertFile = filepath.Join(dir, "tls.crt")
	s.KeyFile = filepath.Join(dir, "tls.key")
	s.CAFile = s.CertFile
	if err = os.WriteFile(s.CertFile, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(s.KeyFile, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	copyUsers := map[string]string{}
	for k, v := range users {
		copyUsers[k] = v
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns[conn] = true
			s.wg.Add(1)
			s.mu.Unlock()
			go func() {
				defer s.wg.Done()
				defer func() { conn.Close(); s.mu.Lock(); delete(s.conns, conn); s.mu.Unlock() }()
				s.serve(ctx, conn, mode, copyUsers)
			}()
		}
	}()
	t.Cleanup(s.Close)
	return s
}
func (s *Server) Close() {
	s.cancel()
	s.listener.Close()
	s.mu.Lock()
	for conn := range s.conns {
		conn.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}
func (s *Server) Commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.commands...)
}
func unquote(s string) (string, string, bool) {
	if len(s) == 0 || s[0] != '"' {
		return "", "", false
	}
	var out strings.Builder
	for i := 1; i < len(s); i++ {
		if s[i] == '"' {
			return out.String(), strings.TrimSpace(s[i+1:]), true
		}
		if s[i] == '\\' {
			i++
			if i == len(s) {
				return "", "", false
			}
		}
		out.WriteByte(s[i])
	}
	return "", "", false
}

// MessageContent and AttachmentContent are fixed payloads for byte-stream assertions.
// SetMailbox changes only the isolated fixture's authoritative summary view.
func (s *Server) SetInternalDate(login, date string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.internalDates == nil {
		s.internalDates = map[string]string{}
	}
	s.internalDates[login] = date
}

func (s *Server) SetMailbox(validity uint32, uids []uint32, flagged bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.validity = validity
	s.uids = append([]uint32{}, uids...)
	s.flagged = flagged
}

func MessageContent() []byte {
	return []byte("Subject: fixture\r\nContent-Type: text/plain\r\n\r\n" + strings.Repeat("mail body line\r\n", 22000))
}
func AttachmentContent() []byte { return []byte("fixture attachment\n") }

func (s *Server) serve(ctx context.Context, conn net.Conn, mode string, users map[string]string) {
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	write := func(v string) { fmt.Fprint(conn, v+"\r\n") }
	write("* OK Mail fixture")
	authenticatedLogin := ""
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), 16384)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return
		}
		tag, command := fields[0], strings.ToUpper(fields[1])
		s.mu.Lock()
		s.commands = append(s.commands, command)
		validity := s.validity
		uids := append([]uint32{}, s.uids...)
		flagged := s.flagged
		internalDate := s.internalDates[authenticatedLogin]
		if internalDate == "" {
			internalDate = "13-Nov-2026 10:00:00 +0000"
		}
		s.mu.Unlock()
		switch command {
		case "CAPABILITY":
			if mode == "stall" {
				<-ctx.Done()
				return
			}
			if mode == "oversized" {
				write("* CAPABILITY " + strings.Repeat("x", 5000))
				return
			}
			caps := "* CAPABILITY IMAP4rev1 IDLE CONDSTORE"
			if mode == "plain" {
				caps += " AUTH=PLAIN SASL-IR"
			}
			if mode == "continuation" {
				caps += " AUTH=PLAIN"
			}
			write(caps)
			write(tag + " OK capabilities")
		case "AUTHENTICATE":
			encoded := ""
			if len(fields) == 4 {
				encoded = fields[3]
			} else {
				write("+ ")
				if !scanner.Scan() {
					return
				}
				encoded = scanner.Text()
			}
			raw, err := base64.StdEncoding.DecodeString(encoded)
			parts := strings.Split(string(raw), "\x00")
			clear(raw)
			if err != nil || len(parts) != 3 || parts[1] == "" || users[parts[1]] != parts[2] {
				write(tag + " NO authentication denied")
			} else {
				authenticatedLogin = parts[1]
				write(tag + " OK authenticated")
			}
		case "LOGIN":
			rest := strings.TrimSpace(strings.TrimPrefix(line, tag+" "+fields[1]))
			login, rest, ok := unquote(rest)
			if !ok {
				return
			}
			password, _, ok := unquote(rest)
			if !ok || login == "" || users[login] != password {
				write(tag + " NO authentication denied")
			} else {
				authenticatedLogin = login
				write(tag + " OK authenticated")
			}
		case "LIST":
			write(`* LIST (\HasNoChildren) "/" INBOX`)
			write(`* LIST (\Noselect \HasChildren) NIL "Archive"`)
			write(`* LIST () "/" "&BB8EPgRHBEIEMA-"`)
			write(`* LIST () "/" {7}`)
			write("Reports")
			write(tag + " OK folders")
		case "EXAMINE":
			write(fmt.Sprintf("* %d EXISTS", len(uids)))
			write("* 0 RECENT")
			write(`* FLAGS (\Seen \Flagged)`)
			write(fmt.Sprintf("* OK [UIDVALIDITY %d] current", validity))
			write("* OK [UIDNEXT 103] next")
			write(tag + " OK [READ-ONLY] selected")
		case "UID":
			if len(fields) == 6 && fields[2] == "FETCH" && fields[4] == "(UID" && fields[5] == "RFC822.SIZE)" {
				id, e := strconv.ParseUint(fields[3], 10, 32)
				if e != nil {
					return
				}
				if id == 101 || id == 102 {
					write(fmt.Sprintf("* %d FETCH (RFC822.SIZE %d UID %d)", id-100, len(MessageContent()), id))
				}
				write(tag + " OK size")
				continue
			}
			if len(fields) == 6 && fields[2] == "FETCH" && fields[4] == "(UID" && strings.HasPrefix(fields[5], "BODY.PEEK[") {
				id, e := strconv.ParseUint(fields[3], 10, 32)
				if e != nil {
					return
				}
				selector := strings.TrimSuffix(strings.TrimPrefix(fields[5], "BODY.PEEK["), ")")
				end := strings.Index(selector, "]<")
				if end < 0 || !strings.HasSuffix(selector, ">") {
					return
				}
				section := selector[:end]
				bounds := strings.Split(selector[end+2:len(selector)-1], ".")
				if len(bounds) != 2 {
					return
				}
				offset, e := strconv.ParseInt(bounds[0], 10, 64)
				if e != nil {
					return
				}
				count, e := strconv.ParseInt(bounds[1], 10, 64)
				if e != nil || count < 1 || count > 256<<10 {
					return
				}
				payload := MessageContent()
				switch section {
				case "":
				case "1":
					payload = []byte("hello world\n")
				case "2":
					payload = []byte(base64.StdEncoding.EncodeToString(AttachmentContent()))
				default:
					return
				}
				if id != 101 && id != 102 {
					write(tag + " OK absent")
					continue
				}
				if offset < 0 || offset >= int64(len(payload)) {
					return
				}
				last := offset + count
				if last > int64(len(payload)) {
					last = int64(len(payload))
				}
				payload = payload[offset:last]
				// UID deliberately follows the literal to exercise server attribute ordering.
				write(fmt.Sprintf("* %d FETCH (BODY[%s]<%d> {%d}", id-100, section, offset, len(payload)))
				if mode == "download-truncated" {
					_, _ = conn.Write(payload[:len(payload)/2])
					return
				}
				_, _ = conn.Write(payload)
				if mode == "download-wrong-uid" {
					id = 999
				}
				write(fmt.Sprintf(" UID %d)", id))
				if mode == "download-incomplete" {
					return
				}
				write(tag + " OK bytes")
				continue
			}

			if len(fields) == 6 && fields[2] == "FETCH" && fields[4] == "(UID" && fields[5] == "BODYSTRUCTURE)" {
				id, err := strconv.ParseUint(fields[3], 10, 32)
				if err != nil {
					return
				}
				if id == 101 || id == 102 {
					write(fmt.Sprintf(`* %d FETCH (UID %d BODYSTRUCTURE (("TEXT" "PLAIN" ("CHARSET" "UTF-8") NIL NIL "8BIT" 12 1 NIL NIL)("APPLICATION" "PDF" ("NAME" "report.pdf") "<report>" NIL "BASE64" 28 NIL ("ATTACHMENT" ("FILENAME*" "utf-8''report%%20final.pdf"))) "MIXED" ("BOUNDARY" "fixture") NIL))`, id-100, id))
				}
				write(tag + " OK structure")
				continue
			}
			if len(fields) != 9 || strings.ToUpper(fields[2]) != "FETCH" {
				write(tag + " BAD unsupported")
				return
			}
			bounds := strings.Split(fields[3], ":")
			if len(bounds) != 2 {
				return
			}
			lo, e := strconv.ParseUint(bounds[0], 10, 32)
			if e != nil {
				return
			}
			hi, e := strconv.ParseUint(bounds[1], 10, 32)
			if e != nil {
				return
			}
			for sequence, rawID := range uids {
				id := uint64(rawID)
				if id < lo || id > hi {
					continue
				}
				subject := `"Hello world"`
				if id == 102 {
					subject = `"=?UTF-8?B?0J/RgNC40LLQtdGC?="`
				}
				flags := `\Seen`
				if flagged {
					flags += ` \Flagged`
				}
				write(fmt.Sprintf(`* %d FETCH (UID %d FLAGS (%s) INTERNALDATE %q RFC822.SIZE 123 ENVELOPE ("Fri, 13 Nov 2026 10:00:00 +0000" %s (("Alice" NIL "alice" "example.test")) NIL NIL ((NIL NIL "bob" "example.test")) NIL NIL NIL "<message-%d@example.test>"))`, sequence+1, id, flags, internalDate, subject, id))
			}
			write(tag + " OK fetched")

		case "LOGOUT":
			write("* BYE")
			write(tag + " OK logout")
			return
		default:
			write(tag + " BAD command not allowed")
			return
		}
	}
}
