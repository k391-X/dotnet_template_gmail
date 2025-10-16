using SmtpGmailDemo.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<EmailSettings>(
    builder.Configuration.GetSection("EmailSettings")
);

builder.Services.AddTransient<EmailService>();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Bật routing cho controller 
app.MapControllers();

//app.MapControllerRoute(
//    name: "/",
//    pattern: "{controller=Email}/{action=Index}"
//);

app.MapControllerRoute(
    name: "/",
    pattern: "{controller=Email}/{action=SendTest}"
);

app.Run();
