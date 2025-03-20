using Microsoft.Extensions.Options;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using tsa.Config;

namespace tsa.Service
{
    public interface ICertificateService
    {
        byte[] GenerateTSACertificateWithRootCA();
    }

    internal class PasswordFinder : IPasswordFinder
    {
        private readonly char[] _password;
        public PasswordFinder(string password)
        {
            _password = password.ToCharArray();
        }

        public char[] GetPassword() => _password;
    }

    public class CertificateService : ICertificateService
    {
        private readonly CertificateConfig _config;

        public CertificateService(IOptions<CertificateConfig> options)
        {
            _config = options.Value;
        }

        public byte[] GenerateTSACertificateWithRootCA()
        {
            var rootCert = LoadRootCACertificate();
            var rootKey = LoadRootPrivateKey();

            var keyPair = GenerateRsaKeyPair();

            var tsaCertGenerator = new X509V3CertificateGenerator();
            var serialNumber = BigInteger.ProbablePrime(120, new SecureRandom());
            tsaCertGenerator.SetSerialNumber(serialNumber);
            tsaCertGenerator.SetIssuerDN(rootCert.SubjectDN);
            tsaCertGenerator.SetSubjectDN(new X509Name("CN=Test TSA, O=Test, C=KR"));
            tsaCertGenerator.SetNotBefore(DateTime.UtcNow);
            tsaCertGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
            tsaCertGenerator.SetPublicKey(keyPair.Public);

            tsaCertGenerator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature));
            var ekuOids = new ExtendedKeyUsage(new List<DerObjectIdentifier> { KeyPurposeID.IdKPTimeStamping });
            tsaCertGenerator.AddExtension(X509Extensions.ExtendedKeyUsage, true, ekuOids);

            var signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", rootKey);
            var tsaCertificate = tsaCertGenerator.Generate(signatureFactory);

            X509Certificate2 tsaCert = ConvertToPfx(tsaCertificate, keyPair.Private, _config.GeneralPassword);
            return tsaCert.Export(X509ContentType.Pkcs12, _config.GeneralPassword);
        }

        private Org.BouncyCastle.X509.X509Certificate LoadRootCACertificate()
        {
            var bytes = File.ReadAllBytes(_config.RootCAPath);

            var parser = new X509CertificateParser();
            return parser.ReadCertificate(bytes);
        }

        private AsymmetricKeyParameter LoadRootPrivateKey()
        {
            using (var reader = new StreamReader(_config.RootKeyPath))
            {
                var pemReader = new PemReader(reader, new PasswordFinder(_config.RootPassword));
                var pemObject = pemReader.ReadObject();

                if (pemObject is AsymmetricCipherKeyPair keyPair)
                {
                    return keyPair.Private;
                }
                else if (pemObject is AsymmetricKeyParameter privateKey)
                {
                    return privateKey;
                }
                else
                {
                    throw new Exception("❌ 잘못된 개인키 형식입니다!");
                }
            }
        }

        private static AsymmetricCipherKeyPair GenerateRsaKeyPair()
        {
            var keyGenParam = new KeyGenerationParameters(new SecureRandom(), 2048);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenParam);
            return keyPairGenerator.GenerateKeyPair();
        }

        private static X509Certificate2 ConvertToPfx(Org.BouncyCastle.X509.X509Certificate bcCert, AsymmetricKeyParameter bcPrivateKey, string password)
        {
            byte[] encodedCert = bcCert.GetEncoded();
            var publicOnlyCert = new X509Certificate2(encodedCert);

            var rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)bcPrivateKey);
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportParameters(rsaParams);

                var certWithKey = publicOnlyCert.CopyWithPrivateKey(rsa);
                return new X509Certificate2(certWithKey.Export(X509ContentType.Pkcs12, password), password,
                    X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
            }
        }
    }
}
