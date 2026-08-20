using Vigil.Infrastructure;
using Vigil.Infrastructure.Tier1;
using Vigil.Worker;

var builder = Host.CreateApplicationBuilder(args);

// Local-only overrides (API keys, personal settings). This file is gitignored
// (appsettings.*.Local.json), so secrets never enter git history.
builder.Configuration.AddJsonFile("appsettings.Development.Local.json", optional: true, reloadOnChange: true);

builder.Services.AddVigilPersistence(builder.Configuration);
builder.Services.AddVigilMachineLearning(builder.Configuration, builder.Environment.ContentRootPath);
builder.Services.AddVigilThreatIntel(builder.Configuration);
builder.Services.AddVigilLlm(builder.Configuration);
builder.Services.AddScoped<Tier1Pipeline>();
builder.Services.AddHostedService<JobConsumerService>();

var host = builder.Build();
host.Run();
