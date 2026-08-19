using Vigil.Infrastructure;
using Vigil.Infrastructure.Tier1;
using Vigil.Worker;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddVigilPersistence(builder.Configuration);
builder.Services.AddScoped<Tier1Pipeline>();
builder.Services.AddHostedService<JobConsumerService>();

var host = builder.Build();
host.Run();
