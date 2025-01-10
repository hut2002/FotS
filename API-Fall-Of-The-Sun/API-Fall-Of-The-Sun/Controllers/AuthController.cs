using Microsoft.AspNetCore.Mvc;
using API_Fall_Of_The_Sun.Data;
using API_Fall_Of_The_Sun.Models;
using BCrypt.Net;
using API_Fall_Of_The_Sun.Data.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data
using API_Fall_Of_The_Sun.Services;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Authorization;


namespace API_Fall_Of_The_Sun.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration;

        public AuthController(AppDbContext context, IEmailService emailService, IConfiguration configuration)
        {
            _context = context;
            _emailService = emailService;
            _configuration = configuration;

            if (string.IsNullOrEmpty(_configuration["Jwt:Key"]))
            {
                throw new InvalidOperationException("Klucz JWT nie został poprawnie skonfigurowany.");
            }
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync([FromBody] Models.RegisterRequest request)
        {
            if (request == null)
            {
                return BadRequest("Nie otrzymano danych.");
            }

            Console.WriteLine($"Odebrane dane: Username={request.Username}, Email={request.Email}, Password={request.Password}, RepeatPassword={request.RepeatPassword}");

            if (request.Password != request.RepeatPassword)
            {
                return BadRequest("Hasła nie są takie same.");
            }

            if (_context.Users.Any(u => u.Email == request.Email))
            {
                return BadRequest("Email już istnieje w systemie.");
            }

            if (_context.Users.Any(u => u.Username == request.Username))
            {
                return BadRequest("Nazwa użytkownika już istnieje.");
            }

            var passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);
            var confirmationToken = Guid.NewGuid().ToString();

            var user = new User
            {
                Username = request.Username.Trim(), // Usówa niechciane znaki z początku i końca
                Email = request.Email.Trim(),
                PasswordHash = passwordHash.Trim(),
                ConfirmationToken = confirmationToken.Trim()
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            string confirmationLink = $"{Request.Scheme}://{Request.Host}/api/Auth/confirm-email?token={confirmationToken}";
            await _emailService.SendEmailAsync(
                user.Email,
                "Potwierdź swój e-mail",
                    $"Kliknij w poniższy link, aby potwierdzić swój adres e-mail:\n{confirmationLink}"
            );

            return Ok("Użytkownik został pomyślnie zarejestrowany. Sprawdź swój e-mail, aby potwierdzić konto.");

        }

        [HttpPost("change-password")]
        [Authorize]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
        {
            if (request == null)
            {
                return BadRequest("Nie otrzymano danych.");
            }

            var email = User.FindFirst(ClaimTypes.Email)?.Value;
            var user = _context.Users.FirstOrDefault(u => u.Email == email);

            if (user == null)
            {
                return NotFound("Użytkownik nie istnieje.");
            }

            if (!BCrypt.Net.BCrypt.Verify(request.CurrentPassword, user.PasswordHash))
            {
                return BadRequest("Błędne obecne hasło.");
            }

            if (BCrypt.Net.BCrypt.Verify(request.NewPassword, user.PasswordHash))
            {
                return BadRequest("Nowe hasło nie może być takie samo jak obecne.");
            }

            user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.NewPassword);
            await _context.SaveChangesAsync();

            return Ok("Hasło zostało zmienione.");
        }

        [HttpGet("confirm-email")]
        public IActionResult ConfirmEmail(string token)
        {
            var user = _context.Users.FirstOrDefault(u => u.ConfirmationToken == token);
            if (user == null)
            {
                return BadRequest("Nieprawidłowy token.");
            }

            user.EmailConfirmed = true;
            user.ConfirmationToken = null;
            _context.SaveChanges();

            return Ok("Adres e-mail został potwierdzony!");
        }

        private string GenerateJwtToken(User user)
        {
            var key = Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, user.Username),
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim(ClaimTypes.NameIdentifier, user.UserId.ToString())
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                Issuer = _configuration["Jwt:Issuer"],
                Audience = _configuration["Jwt:Audience"],
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] API_Fall_Of_The_Sun.Models.LoginRequest request)
        {
            Console.WriteLine($"Próba logowania. Email: {request.Email}, Password: {request.Password}");

            if (string.IsNullOrEmpty(request.Email))
            {
                Console.WriteLine("Email jest pusty.");
                return BadRequest("Email nie może być pusty.");
            }

            var user = _context.Users.FirstOrDefault(u => u.Email == request.Email);

            if (user == null)
            {
                Console.WriteLine("Nie znaleziono użytkownika o podanym emailu.");
                return Unauthorized("Nieprawidłowy email lub hasło.");
            }

            if (user.EmailConfirmed == false)
            {
                Console.WriteLine("Konto nie zostało potwierdzone.");
                return Unauthorized("Adres e-mail nie został potwierdzony.");
            }

            if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
            {
                Console.WriteLine("Hasło jest nieprawidłowe.");
                return Unauthorized("Nieprawidłowy email lub hasło.");
            }

            Console.WriteLine("Logowanie zakończone sukcesem.");

            var token = GenerateJwtToken(user);
            return Ok(new
            {
                Message = "Zalogowano pomyślnie",
                Username = user.Username,
                Email = user.Email,
                Token = token,
                UserId = user.UserId
            });
        }

    }
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _context;

        public UserController(AppDbContext context)
        {
            _context = context;
        }

        [HttpGet("info")]
        [Authorize]
        public IActionResult GetUserInfo()
        {
            var email = User.FindFirst(ClaimTypes.Email)?.Value;
            var user = _context.Users.FirstOrDefault(u => u.Email == email);


            if (string.IsNullOrEmpty(email))
            {
                return Unauthorized("Nie udało się pobrać danych użytkownika.");
            }

            if (user == null)
            {
                return NotFound("Użytkownik nie istnieje.");
            }

            return Ok(new
            {
                Username = user.Username,
                Email = user.Email
            });
        }
    }
}
