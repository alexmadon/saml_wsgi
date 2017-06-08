# saml_wsgi
## Minimal SAMLv2 IdP (Identity Provider) designed for Alfresco testing and QA


This is a minimal IdP (Identity Provider) that will allow you to test Alfresco SAML SP (Service Provider).

It runs with python 3.5+.
The only dependancy is xmlsec1

On a ubuntu/debian system :

```bash
apt-get install xmlsec1
```

You will need a pair of private and public keys.

```bash
------ example---------
# Create the CA Key and Certificate for signing Client Certs
openssl genrsa -des3 -out ca.key 4096
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj '/CN=Alex CA'

# Create the Server Key, CSR, and Certificate
openssl genrsa -des3 -out server.key 1024
(or 
openssl genrsa  -out server.key 1024)
openssl req -new -key server.key -out server.csr -subj '/CN=server1.foo'

# We're self signing our own server cert here.  This is a no-no in production.
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 
01 -out server.crt
-------------------------
```

The IdP needs both keys to run.
You will need to upload the public key to your alfresco SP.

Config can be done using command line (use the -h option for help) or modifying the config.ini file.


