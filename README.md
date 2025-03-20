## RFC 3161 TSA Sample .NET Web API
The timestamp request responds with a TSQ based on a test certificate.  
Since the certificate is not trusted, it should only be used for testing purposes.  
When requesting tsa, it responds with a self-signed certificate.  
When requesting tsa-rootca, it responds with a chain of trust certificate.  

## Environment
.NET 8, Visual Studio 2022

## Self-Signed Certificate Setup
To use a self-signed certificate, you need the crt file and privateKey file in the assets folder.  
These files are provided by default, but if you want, you can generate the crt and privateKey files using OpenSSL, then copy them into the assets folder and configure the CertificateConfig in appsettings.json.

## OpenSSL
```
# Generate private key
openssl genrsa -aes256 -out private.key 2048

# Generate CSR
openssl req -new -key private.key -out request.csr

# Generate CRT (rootCA)
openssl x509 -req -days 3650 -in request.csr -signkey private.key -out cert.crt

# Generate TSQ
openssl ts -query -data test.txt -no_nonce -sha256 -cert -out test.tsq

# TSA request
curl -X POST --data-binary @test.tsq -H "Content-Type: application/timestamp-query" https://localhost:7253/tsa-rootca -o test.tsr

# Verify TSR
openssl ts -reply -in test.tsr -text
```