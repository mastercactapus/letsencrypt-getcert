package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/ericchiang/letsencrypt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"sync"
)

const acmeURL = "https://acme-v01.api.letsencrypt.org/directory"

// const acmeURL = "http://localhost:4000/directory"

var supportedChallengs = []string{
	letsencrypt.ChallengeHTTP,
}

var (
	mainCmd = &cobra.Command{}

	genCmd = &cobra.Command{
		Use:   "generate <domains...>",
		Short: "Generate and sign new certificate(s).",
		Run:   runGen,
	}

	signCmd = &cobra.Command{
		Use:   "sign <CSR files...>",
		Short: "Fulfill existing CSR(s).",
		Run:   runSign,
	}
)

func init() {
	mainCmd.PersistentFlags().StringP("bind", "b", ":80", "Bind address. The binding addres:port for the server. Note, port 80 on the domain(s) must be mapped to this address.")
	mainCmd.PersistentFlags().StringP("acme-url", "u", acmeURL, "ACME URL. URL to the ACME directory to use.")
	mainCmd.PersistentFlags().StringP("output", "o", "-", "Output file. The signed certificate will be saved here. If set to -, stdout will be used. (the default)")
	mainCmd.PersistentFlags().StringP("account-key", "k", "acme.key", "ACME account key (PEM format). The account key to use with this CA. If it doesn't exist, one will be generated.")
	log.SetLevel(log.DebugLevel)
}

type HTTPChallengeResponder struct {
	net.Listener
	*sync.RWMutex
	path, resource string
}

func NewHTTPChallengeResponder(address string) (*HTTPChallengeResponder, error) {
	l, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	h := &HTTPChallengeResponder{
		Listener: l,
		RWMutex:  new(sync.RWMutex),
	}
	log.Debugln("Listening on", address)
	go http.Serve(l, h)
	return h, nil
}
func (h *HTTPChallengeResponder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.RLock()
	defer h.RUnlock()
	if r.URL.Path != h.path {
		log.WithFields(log.Fields{"host": r.Host, "path": r.URL.Path}).Warnln("Bad Request")
		http.NotFound(w, r)
		return
	}
	log.WithFields(log.Fields{"host": r.Host, "path": r.URL.Path}).Infoln("Success")

	io.WriteString(w, h.resource)
}
func (h *HTTPChallengeResponder) SetResource(path, resource string) {
	h.Lock()
	defer h.Unlock()
	log.WithFields(log.Fields{"path": path, "resource": resource}).Debugln("SetResource")
	h.path = path
	h.resource = resource
}

func newCSR(domain string) (*x509.CertificateRequest, *rsa.PrivateKey, error) {
	log.WithField("domain", domain).Debugln("Generating 4096-bit RSA key")
	certKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          &certKey.PublicKey,
		Subject:            pkix.Name{CommonName: domain},
		DNSNames:           []string{domain},
	}
	log.WithField("domain", domain).Debugln("Generating CSR for:", domain)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, certKey)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, err
	}
	return csr, certKey, nil
}

func runGen(cmd *cobra.Command, args []string) {
	url, err := cmd.Flags().GetString("acme-url")
	if err != nil {
		panic(err)
	}
	keyFile, err := cmd.Flags().GetString("account-key")
	if err != nil {
		panic(err)
	}
	bindAddr, err := cmd.Flags().GetString("bind")
	if err != nil {
		panic(err)
	}
	outPath, err := cmd.Flags().GetString("output")
	if err != nil {
		panic(err)
	}

	var out io.Writer
	if outPath == "-" {
		out = os.Stdout
	} else {
		out, err = os.OpenFile(outPath, os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			log.Fatalln(err)
		}
		defer out.(io.Closer).Close()
	}

	cli, err := letsencrypt.NewClient(url)
	if err != nil {
		log.Fatalln(err)
	}

	var accountKey *rsa.PrivateKey
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		log.Debugln("Generating new account key")
		accountKey, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			log.Fatalln(err)
		}
		if _, err = cli.NewRegistration(accountKey); err != nil {
			log.Fatalln("new registration failed:", err)
		}
		b := &pem.Block{
			Bytes: x509.MarshalPKCS1PrivateKey(accountKey),
			Type:  "ACME Account Key",
		}
		pemData := pem.EncodeToMemory(b)
		err = ioutil.WriteFile(keyFile, pemData, 0600)
		if err != nil {
			log.Fatalln(err)
		}
	}

	if accountKey == nil {
		pemData, err := ioutil.ReadFile(keyFile)
		if err != nil {
			log.Fatalln(err)
		}
		b, _ := pem.Decode(pemData)
		if b.Type != "ACME Account Key" {
			log.Fatalln("Invalid account key type:", b.Type)
		}
		accountKey, err = x509.ParsePKCS1PrivateKey(b.Bytes)
		if err != nil {
			log.Fatalln(err)
		}
	}

	h, err := NewHTTPChallengeResponder(bindAddr)
	if err != nil {
		log.Fatalln(err)
	}

	for _, domain := range args {
		log.Infoln("Generating certificate for:", domain)

		l := log.WithField("domain", domain)
		csr, key, err := newCSR(domain)
		if err != nil {
			l.Fatalln("certificate generation failed:", err)
		}
		l.Debug("asking for challenges")
		auth, _, err := cli.NewAuthorization(accountKey, "dns", domain)
		if err != nil {
			l.Fatalln(err)
		}
		chals := auth.Combinations(supportedChallengs...)
		if len(chals) == 0 {
			l.Fatalln("no supported challenge combinations")
		}

		for _, chal := range chals {
			for _, chal := range chal {
				l.Debug("challenge:", chal.Type)
				if chal.Type != letsencrypt.ChallengeHTTP {
					log.Fatalln("unsupported challenge type was requested")
				}
				path, resource, err := chal.HTTP(accountKey)
				if err != nil {
					l.Fatalln(err)
				}
				h.SetResource(path, resource)
				err = cli.ChallengeReady(accountKey, chal)
				if err != nil {
					l.Fatalln(err)
				}
			}
		}

		cert, err := cli.NewCertificate(accountKey, csr)
		if err != nil {
			l.Fatalln(err)
		}
		err = pem.Encode(out, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		if err != nil {
			l.Fatalln(err)
		}

		err = pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		if err != nil {
			l.Fatalln(err)
		}

	}
}
func runSign(cmd *cobra.Command, args []string) {

}

func fulfill(csr *x509.CertificateRequest) error {
	return nil
}

func main() {
	mainCmd.AddCommand(genCmd, signCmd)
	mainCmd.Execute()
}
