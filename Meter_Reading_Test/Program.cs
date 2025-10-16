using Meter_Reading_Test.Models;
using Microsoft.Extensions.Http;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

// Configure CORS for cross-origin requests
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
    {
        var frontendUrls = builder.Configuration.GetSection("FrontendUrls").Get<string[]>() ?? new[] { "http://localhost:5000" };
        policy.WithOrigins(frontendUrls)
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials();  // Important for cookies
    });
});

// Configure API settings
builder.Services.Configure<ApiSettings>(builder.Configuration.GetSection("ApiSettings"));

// Add HttpClient service for API calls
builder.Services.AddHttpClient();

// Configure HttpClient timeout (optional)
builder.Services.Configure<HttpClientFactoryOptions>(options =>
{
    options.HttpClientActions.Add(client =>
    {
        client.Timeout = TimeSpan.FromSeconds(30); // 30 second timeout
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

// Use CORS policy
app.UseCors("AllowFrontend");

app.UseRouting();

app.UseAuthorization();

app.MapRazorPages();

// Set default route to SignIn page
app.MapGet("/", () => Results.Redirect("/Authenitcation/SignIn"));

app.Run();
