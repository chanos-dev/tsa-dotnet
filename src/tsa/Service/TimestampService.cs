using Microsoft.Extensions.Options;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509.Store;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using tsa.Config;

namespace tsa.Service
{
    public interface ITimestampService
    {
        byte[] GenerateTSAResponse(byte[] certBytes, byte[] requestBytes);
    }

    public class TimestampService : ITimestampService
    {
        private readonly CertificateConfig _config;

        public TimestampService(IOptions<CertificateConfig> options)
        {
            _config = options.Value;
        }

        public byte[] GenerateTSAResponse(byte[] certBytes, byte[] requestBytes)
        {
            try
            {
                X509Certificate2 cert = new(certBytes,
                    _config.GeneralPassword,
                    X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);

                AsymmetricKeyParameter privateKey = LoadPrivateKey(cert);
                Org.BouncyCastle.X509.X509Certificate bcCert = DotNetUtilities.FromX509Certificate(cert);

                TimeStampRequest tsaRequest = new TimeStampRequest(requestBytes);
                byte[] hash = tsaRequest.GetMessageImprintDigest();
                BigInteger serialNumber = new(Guid.NewGuid().ToByteArray());
                string tsaPolicyOid = tsaRequest.ReqPolicy ?? "1.2.3.4.5.6.7";

                TimeStampTokenGenerator tsaGenerator = new(
                    privateKey,
                    bcCert,
                    TspAlgorithms.Sha256,
                    tsaPolicyOid);

                var certList = new List<Org.BouncyCastle.X509.X509Certificate> { bcCert };
                var certStore = X509StoreFactory.Create("Certificate/Collection", new X509CollectionStoreParameters(certList));

                tsaGenerator.SetCertificates(certStore);
                tsaGenerator.SetAccuracySeconds(1);
                tsaGenerator.SetOrdering(false);
                tsaGenerator.SetTsa(new GeneralName(X509Name.GetInstance(bcCert.SubjectDN)));

                TimeStampResponseGenerator responseGenerator = new TimeStampResponseGenerator(
                    tsaGenerator, TspAlgorithms.Allowed);

                TimeStampResponse response = responseGenerator.Generate(tsaRequest, serialNumber, DateTime.UtcNow);

                if (response.TimeStampToken is null)
                    throw new Exception("error : TimestampToken is null");

                byte[] responseBytes = response.GetEncoded();

                return responseBytes;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error in GenerateTsaResponse: {ex.Message}");
                throw;
            }
        }

        private AsymmetricKeyParameter LoadPrivateKey(X509Certificate2 cert)
        {
            using RSA? rsa = cert.GetRSAPrivateKey();

            if (rsa is null)
                throw new Exception("error : load private key.");

            return DotNetUtilities.GetKeyPair(rsa).Private;
        }
    }

}
