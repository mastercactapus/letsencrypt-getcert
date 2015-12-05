# letsencrypt-getcert

This tool uses the LE CA and the ACME protocol to generate a certificate, CSR, and sign it. If you already have a CSR that can be used as well.

## Install

Installation can be done with `go get`

```bash
go get -u github.com/mastercactapus/letsencrypt-getcert
```

## Usage

Note that should you need to include the full certificate chain, the `--chain` option will include ALL LetsEncrypt certificates in the output.

### Generating a new certificate

You will need to temporarily make port 80 available and have sudo/root access to the server your domain(s) point to.

```bash

letsencrypt-getcert generate --chain example.com
# example.com.crt.pem and example.com.key.pem should be in the current directory
```

You can now move and/or reference `example.com.crt.pem` and `example.com.key.pem` from your TLS services.


### Using an existing CSR

When using an existing CSR, the tool will automatically use the CommonName, so the domain name doesn't need to be specified.

```bash

letsencrypt-getcert sign ./example.csr
# example.com.crt.pem should be in the current directory
```


### Advanced

The full set of options can be printed by running `letsencrypt-getcert help`

```
Simple utility for generating signed TLS certificates.

Usage: 
  letsencrypt-getcert [command]

Available Commands: 
  generate    Generate and sign new certificate(s).
  sign        Fulfill existing CSR(s).
  help        Help about any command

Flags:
  -k, --account-key="acme.key": ACME account key (PEM format). The account key to use with this CA. If it doesn't exist, one will be generated.
  -u, --acme-url="https://acme-v01.api.letsencrypt.org/directory": ACME URL. URL to the ACME directory to use.
  -b, --bind=":80": Bind address. The binding address:port for the server. Note, port 80 on the domain(s) must be mapped to this address.
      --bits=4096: Bits for RSA key generation.
      --chain=false: Include full chain. If set, download and include all LE certificates in the chain.
  -h, --help=false: help for letsencrypt-getcert
  -d, --output-dir=".": Output directory. Certificates and keys will be stored here.
  -v, --verbose=false: Verbose mode. Logs extra messages for debugging.


Use "letsencrypt-getcert [command] --help" for more information about a command.

```
