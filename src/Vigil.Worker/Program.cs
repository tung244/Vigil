var builder = Host.CreateApplicationBuilder(args);

// Queue consumer + Tier 1/Tier 2 pipeline are registered here from Step 4 onward.

var host = builder.Build();
host.Run();
