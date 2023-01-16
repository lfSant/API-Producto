using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

using APICORE.Models;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.Extensions.Configuration;
using System.Data.SqlClient;
using System.Data;
using Microsoft.AspNetCore.Cors;

namespace APICORE.Controllers
{
    [EnableCors("ReglasCors")]
    [Route("api/[controller]")]
    [ApiController]
    public class AutenticacionController : ControllerBase
    {
        private readonly string cadenaSQL;

        private readonly string secretKey;
        public AutenticacionController(IConfiguration configKey, IConfiguration configServ)
        {
            secretKey = configKey.GetSection("settings").GetSection("secretKey").ToString();
            cadenaSQL = configServ.GetConnectionString("CadenaSQL");
        }

        [HttpPost]
        [Route("validar")]
        public IActionResult Validar([FromBody] Usuario request)
        {
            List<Usuario> lista = new List<Usuario>();
            try
            {

                using (var conexion = new SqlConnection(cadenaSQL))
                {
                    conexion.Open();
                    var cmd = new SqlCommand("sp_lista_usuarios", conexion);
                    cmd.CommandType = CommandType.StoredProcedure;
                    using (var rd = cmd.ExecuteReader())
                    {
                        while (rd.Read())
                        {
                            lista.Add(new Usuario()
                            {
                                IdUsuario = Convert.ToInt32(rd["IdUsuario"]),
                                Correo = rd["Correo"].ToString(),
                                Clave = rd["Clave"].ToString()
                            });
                        }
                    }
                }

                //Recorre la lista "lista"
                bool encontroUsuario = false;
                foreach (Usuario usuario in lista)
                {
                    if (request.Correo == usuario.Correo && request.Clave == usuario.Clave)
                    {
                        encontroUsuario = true;
                        var KeyBytes = Encoding.ASCII.GetBytes(secretKey);
                        var claims = new ClaimsIdentity();

                        claims.AddClaim(new Claim(ClaimTypes.NameIdentifier, request.Correo));

                        //Condiguracion del token
                        var tokenDescriptor = new SecurityTokenDescriptor
                        {
                            Subject = claims,
                            Expires = DateTime.UtcNow.AddMinutes(5),
                            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(KeyBytes), SecurityAlgorithms.HmacSha256Signature)
                        };
                        var tokenHandler = new JwtSecurityTokenHandler(); //Manejador de token
                        var token = tokenHandler.CreateToken(tokenDescriptor); //Crea el token
                        string tokencreado = tokenHandler.WriteToken(token); //Lo convierte en string
                        return StatusCode(StatusCodes.Status200OK, new { mensaje = "OK", response = tokencreado });
                    }
                }
                if (encontroUsuario)
                {
                    return StatusCode(StatusCodes.Status200OK, new { mensaje = "OK" });
                }
                else
                {
                    return StatusCode(StatusCodes.Status401Unauthorized, new { mensaje = "Usuario o contraseña incorrectos" });
                }
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new { mensaje = ex.Message });
            }

        }
    }
}
