using Microsoft.AspNetCore.Mvc;
using tsa.Service;

namespace tsa.Endpoint
{
    internal static class TSAEndpoint
    {
        internal static WebApplication MapTSA(this WebApplication app)
        {
            app.MapPost("/tsa", async ([FromServices] ITimestampService tsa,
                [FromServices] ICertificateService certificate,
                [FromServices] ILogger<Program> logger,
                HttpContext context, 
                CancellationToken token) =>
            {
                try
                {
                    using var ms = new MemoryStream();
                    await context.Request.Body.CopyToAsync(ms, token);
                    byte[] requestBytes = ms.ToArray();

                    if (requestBytes is null || requestBytes.Length == 0)
                        return Results.BadRequest("TSA");

                    var cert = certificate.GenerateTSACertificateWithRootCA();

                    var responseBytes = tsa.GenerateTSAResponse(cert, requestBytes);

                    return Results.File(responseBytes, "application/timestamp-reply");
                }
                catch (Exception e)
                {
                    return Results.BadRequest(e.Message);
                }
            });

            return app;
        }
    }
}
