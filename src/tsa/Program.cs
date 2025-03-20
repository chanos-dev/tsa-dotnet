using tsa.Config;
using tsa.Endpoint;
using tsa.Service;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddSingleton<ITimestampService, TimestampService>();
builder.Services.AddSingleton<ICertificateService, CertificateService>();
builder.Services.Configure<CertificateConfig>(builder.Configuration.GetSection(nameof(CertificateConfig)));

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();
app.MapTSA();

app.Run();