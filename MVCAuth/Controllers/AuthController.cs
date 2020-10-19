using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MVCAuth.Models;
using Microsoft.Extensions.Configuration;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Http;

namespace MVCAuth.Controllers
{
    public class AuthController : Controller
    {
        private IConfiguration _config;
        public AuthController(IConfiguration config)
        {
            _config = config;
        }
        public IActionResult Index()
        {
            return View();
        }
        [HttpPost]
        public IActionResult Login([FromForm] LoginModel user)
        {
            if (user.username == "emad" && user.password == "emad")
            {
                var token = GenerateToken(user, 100);
                Response.Cookies.Append("token", token);
                return Ok(token);
            }
            return Unauthorized();
        }
        private string GenerateToken(LoginModel Authuser, int timeExpiration)
        {
            //Header==================
            var SecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:secretkey"]));
            var credential = new SigningCredentials(SecurityKey, SecurityAlgorithms.HmacSha256);
            //Payload=================
            var Claims = new[]
            {
                new Claim("Id",Authuser.username+""),
            };
            #region for Role Identity
            ClaimsIdentity claimsIdentity = new ClaimsIdentity(Claims, "Token");
            // Adding roles code
            // Roles property is string collection but you can modify Select code if it it's not
            claimsIdentity.AddClaims(new List<Claim> { new Claim(ClaimTypes.Role, "admin") });
            #endregion

            var Token = new JwtSecurityToken(
                issuer: "beldor@beldor.com",
                audience: "beldor@beldor.com",
                claimsIdentity.Claims,
                expires: DateTime.Now.AddDays(timeExpiration),
                signingCredentials: credential
                );

            var encodeToken = new JwtSecurityTokenHandler().WriteToken(Token);
            return encodeToken;
        }
    }
}
