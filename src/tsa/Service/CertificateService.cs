using Microsoft.Extensions.Options;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using tsa.Config;

namespace tsa.Service
{
    public interface ICertificateService
    {
        (X509Certificate, AsymmetricKeyParameter) GenerateTSACertificate();
        (X509Certificate, AsymmetricKeyParameter) GenerateTSACertificateWithRootCA();
    }

    public class CertificateService : ICertificateService
    {
        class PasswordFinder : IPasswordFinder
        {
            private readonly char[] _password;

            internal PasswordFinder(string password)
            {
                _password = password.ToCharArray();
            }

            public char[] GetPassword() => _password;
        }

        private readonly CertificateConfig _config;

        public CertificateService(IOptions<CertificateConfig> options)
        {
            _config = options.Value;
        }

        private X509Certificate GenerateX509(X509Name issuerDN,
            AsymmetricKeyParameter privateKey,
            AsymmetricKeyParameter publicKey)
        {
            X509V3CertificateGenerator tsaCertGenerator = new();
            tsaCertGenerator.SetSerialNumber(BigInteger.ProbablePrime(120, new SecureRandom()));
            tsaCertGenerator.SetIssuerDN(issuerDN);
            tsaCertGenerator.SetSubjectDN(new X509Name("CN=Test TSA, O=Test, C=KR"));
            tsaCertGenerator.SetNotBefore(DateTime.UtcNow);
            tsaCertGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
            tsaCertGenerator.SetPublicKey(publicKey);
            tsaCertGenerator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature));

            ExtendedKeyUsage ekuOids = new(new List<DerObjectIdentifier>
            {
                KeyPurposeID.IdKPTimeStamping
            });

            tsaCertGenerator.AddExtension(X509Extensions.ExtendedKeyUsage, true, ekuOids);

            Asn1SignatureFactory signatureFactory = new("SHA256WithRSA", privateKey);
            X509Certificate cert = tsaCertGenerator.Generate(signatureFactory);

            return cert;
        }

        public (X509Certificate, AsymmetricKeyParameter) GenerateTSACertificate()
        {
            AsymmetricCipherKeyPair keyPair = GenerateRsaKeyPair();

            X509Name issuerDN = new("CN=Test TSA, O=Test, C=KR");
            X509Certificate cert = GenerateX509(issuerDN, keyPair.Private, keyPair.Public);

            return (cert, keyPair.Private);
        }

        public (X509Certificate, AsymmetricKeyParameter) GenerateTSACertificateWithRootCA()
        {
            X509Certificate rootCert = LoadRootCACertificate();
            AsymmetricKeyParameter rootKey = LoadRootPrivateKey();
            AsymmetricCipherKeyPair keyPair = GenerateRsaKeyPair();

            X509Certificate cert = GenerateX509(rootCert.SubjectDN, rootKey, keyPair.Public);

            return (cert, keyPair.Private);
        }

        private X509Certificate LoadRootCACertificate()
        {
            var bytes = File.ReadAllBytes(_config.RootCAPath);

            X509CertificateParser parser = new();

            return parser.ReadCertificate(bytes);
        }

        private AsymmetricKeyParameter LoadRootPrivateKey()
        {
            using StreamReader reader = new(_config.RootKeyPath);
            PemReader pemReader = new(reader, new PasswordFinder(_config.RootPassword));
            var pemObject = pemReader.ReadObject();

            if (pemObject is AsymmetricCipherKeyPair keyPair)
                return keyPair.Private;
            else if (pemObject is AsymmetricKeyParameter privateKey)
                return privateKey;
            else
                throw new Exception("Invalid private key format.");
        }

        private AsymmetricCipherKeyPair GenerateRsaKeyPair()
        {
            KeyGenerationParameters keyGenParam = new(new SecureRandom(), 2048);

            RsaKeyPairGenerator keyPairGenerator = new();
            keyPairGenerator.Init(keyGenParam);

            return keyPairGenerator.GenerateKeyPair();
        }
    }
}
