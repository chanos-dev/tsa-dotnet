using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace tsa.Service
{
    public interface ITimestampService
    {
        byte[] GenerateTSR(X509Certificate cert, AsymmetricKeyParameter privateKey, byte[] requestBytes);
    }

    public class TimestampService : ITimestampService
    { 
        public byte[] GenerateTSR(X509Certificate cert, AsymmetricKeyParameter privateKey, byte[] requestBytes)
        {
            TimeStampRequest tsaRequest = new(requestBytes);
            BigInteger serialNumber = new(Guid.NewGuid().ToByteArray());
            string tsaPolicyOid = tsaRequest.ReqPolicy ?? "1.2.3.4.5.6.7";

            TimeStampTokenGenerator tsaGenerator = new(
                privateKey,
                cert,
                TspAlgorithms.Sha256,
                tsaPolicyOid);

            var certStore = X509StoreFactory.Create("Certificate/Collection", 
                new X509CollectionStoreParameters(new List<X509Certificate> { cert }));

            tsaGenerator.SetCertificates(certStore);
            tsaGenerator.SetAccuracySeconds(1);
            tsaGenerator.SetOrdering(false);
            tsaGenerator.SetTsa(new GeneralName(X509Name.GetInstance(cert.SubjectDN)));

            TimeStampResponseGenerator responseGenerator = new(tsaGenerator, TspAlgorithms.Allowed);

            TimeStampResponse response = responseGenerator.Generate(tsaRequest, serialNumber, DateTime.UtcNow);

            if (response.TimeStampToken is null)
                throw new Exception("TimeStampToken is null.");

            return response.GetEncoded(); 
        }
    }
}