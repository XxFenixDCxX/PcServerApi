using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Sockets;
using System.Security.Claims;
using System.Text.Json;

// Diccionario global de procesos levantados
Dictionary<string, System.Diagnostics.Process> RunningProcesses = new();

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors(o => o.AddDefaultPolicy(p => p.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader()));

var jwtKey = Convert.FromBase64String(builder.Configuration["Jwt:Key"]!);
var jwtIssuer = builder.Configuration["Jwt:Issuer"];

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = false,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtIssuer,
            IssuerSigningKey = new SymmetricSecurityKey(jwtKey)
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

string usersFile = @"C:\PcServerApi\users.json";
string servicesFile = @"C:\PcServerApi\services.json";

// Health público
app.MapGet("/health", () =>
    Results.Ok(new { ok = true, time = DateTime.UtcNow, machine = Environment.MachineName })
);

// Login
app.MapPost("/auth/login", (LoginRequest req) =>
{
    if (!File.Exists(usersFile)) return Results.Problem("Users file not found", statusCode: 500);
    var users = JsonSerializer.Deserialize<List<User>>(File.ReadAllText(usersFile)) ?? new();
    var u = users.FirstOrDefault(x => x.Username == req.Username && x.Password == req.Password);
    if (u is null) return Results.Unauthorized();

    var claims = new List<Claim> { new Claim(ClaimTypes.Name, u.Username) };
    foreach (var role in u.Roles) claims.Add(new Claim(ClaimTypes.Role, role));

    var creds = new SigningCredentials(new SymmetricSecurityKey(jwtKey), SecurityAlgorithms.HmacSha256);
    var token = new JwtSecurityToken(
        issuer: jwtIssuer,
        audience: null,
        claims: claims,
        expires: DateTime.UtcNow.AddHours(8),
        signingCredentials: creds
    );
    var jwt = new JwtSecurityTokenHandler().WriteToken(token);

    return Results.Ok(new { token = jwt });
});

// Servicios protegidos
app.MapGet("/services", async (ClaimsPrincipal user) =>
{
    if (!File.Exists(servicesFile)) return Results.Problem("Services file not found", statusCode: 500);
    var services = JsonSerializer.Deserialize<List<Service>>(File.ReadAllText(servicesFile)) ?? new();
    var roles = user.FindAll(ClaimTypes.Role).Select(r => r.Value).ToHashSet();

    var publicIp = await GetPublicIpAsync();

    var result = services
        .Where(s => roles.Contains("admin") || roles.Contains(s.Id))
        .Select(s => new
        {
            s.Id,
            s.Name,
            s.Path,
            Host = publicIp + ":" + s.Port,
            Status = GetServiceStatus(s)
        });

    return Results.Ok(result);
}).RequireAuthorization();

// Encendido de servicio protegido
app.MapPost("/services/{id}/start", (string id) =>
{
    var services = JsonSerializer.Deserialize<List<Service>>(File.ReadAllText(servicesFile)) ?? new();
    var s = services.FirstOrDefault(x => x.Id == id);
    if (s is null) return Results.NotFound();

    var psi = new System.Diagnostics.ProcessStartInfo
    {
        FileName = "powershell.exe",
        Arguments = $"-ExecutionPolicy Bypass -File \"{s.Path}\"",
        UseShellExecute = false,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        RedirectStandardInput = true,
        CreateNoWindow = true,
        WorkingDirectory = Path.GetDirectoryName(s.Path) ?? Environment.CurrentDirectory
    };

    var process = new System.Diagnostics.Process { StartInfo = psi };

    var logFile = Path.Combine("C:\\PcServerApi\\logs", $"{id}.log");
    Directory.CreateDirectory(Path.GetDirectoryName(logFile)!);

    // abrir stream compartido
    var logStream = new StreamWriter(new FileStream(
        logFile,
        FileMode.Append,
        FileAccess.Write,
        FileShare.ReadWrite))
    {
        AutoFlush = true
    };

    process.OutputDataReceived += (sender, e) =>
    {
        if (!string.IsNullOrEmpty(e.Data))
        {
            lock (logStream) // proteger escrituras concurrentes
            {
                logStream.WriteLine(e.Data);
            }
        }
    };

    process.ErrorDataReceived += (sender, e) =>
    {
        if (!string.IsNullOrEmpty(e.Data))
        {
            lock (logStream)
            {
                logStream.WriteLine("[ERR] " + e.Data);
            }
        }
    };

    process.Exited += (s, e) =>
    {
        logStream.Dispose();
    };

    process.Start();
    process.BeginOutputReadLine();
    process.BeginErrorReadLine();

    RunningProcesses[id] = process;

    return Results.Ok(new { started = true });
}).RequireAuthorization();

// Endpoint para los logs de los comandos
app.MapGet("/services/{id}/logs", (string id) =>
{
    var logFile = Path.Combine("C:\\PcServerApi\\logs", $"{id}.log");
    if (!File.Exists(logFile))
        return Results.Ok(new List<string>());

    List<string> lines = new();
    using (var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
    using (var sr = new StreamReader(fs))
    {
        while (!sr.EndOfStream)
        {
            var line = sr.ReadLine();
            if (line != null)
                lines.Add(line);
        }
    }

    var lastLines = lines.TakeLast(200).ToList();
    return Results.Ok(lastLines);
}).RequireAuthorization();

// Endpoint para ver el estado del servidor
app.MapGet("/services/{id}/status", (string id) =>
{
    if (!File.Exists(servicesFile)) return Results.NotFound();

    var services = JsonSerializer.Deserialize<List<Service>>(File.ReadAllText(servicesFile)) ?? new();
    var s = services.FirstOrDefault(x => x.Id == id);
    if (s is null) return Results.NotFound();

    var status = GetServiceStatus(s);
    return Results.Ok(status);
}).RequireAuthorization();


// Endpoint para enviar comandos al servidor
app.MapPost("/services/{id}/command", async (HttpContext http, string id, CommandRequest req) =>
{
    if (!RunningProcesses.TryGetValue(id, out var process))
        return Results.BadRequest("Service not running");

    var user = http.User?.Identity?.Name ?? "unknown";

    var logLine = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}] User={user}, Service={id}, Command=\"{req.Command}\"";

    var auditFile = Path.Combine("C:\\PcServerApi\\logs", "commands_audit.log");
    Directory.CreateDirectory(Path.GetDirectoryName(auditFile)!);

    await File.AppendAllTextAsync(auditFile, logLine + Environment.NewLine);

    await process.StandardInput.WriteLineAsync(req.Command);

    return Results.Ok(new { sent = true });
}).RequireAuthorization();

// Endpoint para parar el servicio
app.MapPost("/services/{id}/stop", (string id) =>
{
    if (!RunningProcesses.TryGetValue(id, out var process) || process.HasExited)
        return Results.BadRequest("Service not running");

    process.Kill(true); // mata proceso y subprocesos
    process.WaitForExit();
    RunningProcesses.Remove(id);

    return Results.Ok(new { stopped = true });
}).RequireAuthorization();

// Endpoint para apagar el ordenador
app.MapPost("/system/shutdown", (ClaimsPrincipal user) =>
{
    var psi = new System.Diagnostics.ProcessStartInfo
    {
        FileName = "shutdown",
        Arguments = "/s /t 0",
        CreateNoWindow = true,
        UseShellExecute = false
    };

    System.Diagnostics.Process.Start(psi);

    return Results.Ok(new { shuttingDown = true });
}).RequireAuthorization();

app.Run("http://0.0.0.0:5000");

// Helpers
ServiceStatus GetServiceStatus(Service s)
{
    if (!RunningProcesses.ContainsKey(s.Id) || RunningProcesses[s.Id].HasExited)
        return new ServiceStatus("offline");

    if (s.Port > 0)
    {
        try
        {
            using var client = new TcpClient();
            client.SendTimeout = 1000;
            client.ReceiveTimeout = 1000;
            client.Connect(s.Host ?? "127.0.0.1", s.Port);
            if (client.Connected)
                return new ServiceStatus("running");
            else
                return new ServiceStatus("starting");
        }
        catch
        {
            return new ServiceStatus("starting");
        }
    }

    return new ServiceStatus("running");
}
async Task<string?> GetPublicIpAsync()
{
    using var http = new HttpClient();
    try
    {
        return await http.GetStringAsync("https://api.ipify.org");
    }
    catch
    {
        return null;
    }
}


// Records
record LoginRequest(string Username, string Password);
record User(string Username, string Password, string[] Roles);
record Service(string Id, string Name, string Path, string? Host = null, int Port = 25565);
record CommandRequest(string Command);
record ServiceStatus(string State, int OnlinePlayers = 0, int MaxPlayers = 0, List<string>? PlayerNames = null);

// Objeto status de Minecraft
record MinecraftStatus(bool Online, int OnlinePlayers, int MaxPlayers, List<string> PlayerNames);
