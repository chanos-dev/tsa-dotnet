using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using tsa.Service;

namespace tsa.Endpoint
{
    internal static class TSAEndpoint
    {
        internal static WebApplication MapTSA(this WebApplication app)
        {
            async Task<IResult> ResponseTSAAsync(ITimestampService tsa,
                Func<(X509Certificate, AsymmetricKeyParameter)> GenerateTSAFunc,
                HttpContext context,
                CancellationToken token)
            {
                try
                {
                    using MemoryStream ms = new();
                    await context.Request.Body.CopyToAsync(ms, token);
                    byte[] tsq = ms.ToArray();

                    if (tsq is null || tsq.Length == 0)
                        return Results.BadRequest("The timestamp request (TSQ) is empty. Please provide a valid request.");

                    (var cert, var key) = GenerateTSAFunc.Invoke();

                    byte[] tsrBytes = tsa.GenerateTSR(cert, key, tsq);

                    return Results.File(tsrBytes, "application/timestamp-reply");
                }
                catch (Exception ex)
                {
                    return Results.BadRequest(ex.Message);
                }
            }

            app.MapPost("/tsa", async ([FromServices] ITimestampService tsa,
                [FromServices] ICertificateService certificate,
                HttpContext context,
                CancellationToken token) =>
            {
                return await ResponseTSAAsync(tsa,
                    certificate.GenerateTSACertificate,
                    context,
                    token);
            });

            app.MapPost("/tsa-rootca", async ([FromServices] ITimestampService tsa,
                [FromServices] ICertificateService certificate,
                HttpContext context,
                CancellationToken token) =>
            {
                return await ResponseTSAAsync(tsa,
                    certificate.GenerateTSACertificateWithRootCA,
                    context,
                    token);
            });

            return app;
        }
    }
}
