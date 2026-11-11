package stream

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pavlith/arc/sdk/contract"
	"github.com/pavlith/arc/sdk/security"
	filesv1 "github.com/pavlith/arc/services/files/api/v1"
	"github.com/pavlith/arc/services/files/modules/objects"
)

func issueTestCA(t *testing.T) (*x509.Certificate,*ecdsa.PrivateKey,[]byte) {
	t.Helper()
	key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
	if err!=nil{t.Fatal(err)}
	now:=time.Now()
	ca:=&x509.Certificate{
		SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"Arc Files stream test CA"},
		NotBefore:now.Add(-time.Hour),NotAfter:now.Add(time.Hour),
		IsCA:true,BasicConstraintsValid:true,
		KeyUsage:x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign,
	}
	der,err:=x509.CreateCertificate(rand.Reader,ca,ca,&key.PublicKey,key)
	if err!=nil{t.Fatal(err)}
	cert,err:=x509.ParseCertificate(der)
	if err!=nil{t.Fatal(err)}
	return cert,key,pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der})
}

func issueTestLeaf(t *testing.T,ca *x509.Certificate,caKey *ecdsa.PrivateKey,server bool,serial int64) ([]byte,[]byte) {
	t.Helper()
	key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
	if err!=nil{t.Fatal(err)}
	name:="gate.internal"
	usage:=x509.ExtKeyUsageClientAuth
	if server{name="files.internal";usage=x509.ExtKeyUsageServerAuth}
	now:=time.Now()
	template:=&x509.Certificate{
		SerialNumber:big.NewInt(serial),Subject:pkix.Name{CommonName:name},
		DNSNames:[]string{name},NotBefore:now.Add(-time.Minute),NotAfter:now.Add(30*time.Minute),
		KeyUsage:x509.KeyUsageDigitalSignature,ExtKeyUsage:[]x509.ExtKeyUsage{usage},
		BasicConstraintsValid:true,
	}
	der,err:=x509.CreateCertificate(rand.Reader,template,ca,&key.PublicKey,caKey)
	if err!=nil{t.Fatal(err)}
	keyRaw,err:=x509.MarshalECPrivateKey(key)
	if err!=nil{t.Fatal(err)}
	return pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}),
		pem.EncodeToMemory(&pem.Block{Type:"EC PRIVATE KEY",Bytes:keyRaw})
}

func TestPrivateMTLSHandshakeRequiresTrustedGateClient(t *testing.T) {
	ca,caKey,caPEM:=issueTestCA(t)
	serverCert,serverKey:=issueTestLeaf(t,ca,caKey,true,2)
	clientCert,clientKey:=issueTestLeaf(t,ca,caKey,false,3)
	private,err:=tls.X509KeyPair(clientCert,clientKey)
	if err!=nil{t.Fatal(err)}
	dir:=t.TempDir()
	write:=func(name string,raw []byte)string{
		p:=filepath.Join(dir,name)
		if err:=os.WriteFile(p,raw,0600);err!=nil{t.Fatal(err)}
		return p
	}
	compiled,err:=contract.Compile(filesv1.Artifact())
	if err!=nil{t.Fatal(err)}
	s,err:=New(Config{
		Listen:"127.0.0.1:0",
		TLSCertFile:write("server.crt",serverCert),
		TLSKeyFile:write("server.key",serverKey),
		ClientCAFile:write("client-ca.crt",caPEM),
		Verify:func(context.Context,string,[]byte)(context.Context,error){return nil,security.ErrDenied},
		Objects:&objects.Module{},Contract:compiled,
	})
	if err!=nil{t.Fatal(err)}
	if err:=s.Start();err!=nil{t.Fatal(err)}
	defer s.Stop(context.Background())
	target:="https://"+s.listener.Addr().String()+DownloadPath
	pool:=x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM){t.Fatal("test root CA missing")}
	makeClient:=func(cert *tls.Certificate,name string,min,max uint16)*http.Client{
		settings:=&tls.Config{RootCAs:pool,ServerName:name,
			MinVersion:min,MaxVersion:max}
		if cert!=nil{settings.Certificates=[]tls.Certificate{*cert}}
		return &http.Client{Transport:&http.Transport{Proxy:nil,TLSClientConfig:settings}}
	}
	approved:=makeClient(&private,"files.internal",tls.VersionTLS13,0)
	resp,err:=approved.Get(target)
	if err!=nil{t.Fatalf("trusted Gate mTLS was rejected: %v",err)}
	_ = resp.Body.Close()
	if resp.StatusCode!=http.StatusUnauthorized {
		t.Fatalf("trusted mTLS did not reach signed-envelope requirement: %d",resp.StatusCode)
	}
	for _,tc:=range []struct{
		name string
		client *http.Client
	}{
		{"no_client_certificate",makeClient(nil,"files.internal",tls.VersionTLS13,0)},
		{"wrong_server_name",makeClient(&private,"other.internal",tls.VersionTLS13,0)},
		{"TLS_1_2_only",makeClient(&private,"files.internal",tls.VersionTLS12,tls.VersionTLS12)},
	} {
		t.Run(tc.name,func(t *testing.T){
			response,err:=tc.client.Get(target)
			if response!=nil{_ = response.Body.Close()}
			if err==nil{
				t.Fatalf("untrusted private mTLS connection accepted: status=%d",response.StatusCode)
			}
		})
	}
}
