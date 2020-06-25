using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace TokenManager
{
    public class JwtHelper
    {
        public static string GenerateToken(IEnumerable<Claim> Claims, string validAudience = null, int lifeSpanInSeconds = 60)
        {
            byte[] key = Convert.FromBase64String(AppKeys.SymmetricJwtKey);
            SymmetricSecurityKey securityKey = new SymmetricSecurityKey(key);
            SecurityTokenDescriptor descriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(Claims),
                Expires = DateTime.UtcNow.AddSeconds(lifeSpanInSeconds),
                Audience = validAudience,
                SigningCredentials = new SigningCredentials(securityKey,
                SecurityAlgorithms.HmacSha256Signature)
            };

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            JwtSecurityToken token = handler.CreateJwtSecurityToken(descriptor);
            return handler.WriteToken(token);
        }
        public static ClaimsPrincipal GetPrincipal(string token,
            string validAudience = null)
        {
            try
            {
                JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
                JwtSecurityToken jwtToken = (JwtSecurityToken)tokenHandler.ReadToken(token);
                if (jwtToken == null)
                    return null;
                byte[] key = Convert.FromBase64String(AppKeys.SymmetricJwtKey);
                TokenValidationParameters parameters = new TokenValidationParameters()
                {
                    RequireExpirationTime = true,
                    ValidateIssuer = false,
                    IssuerSigningKey = new SymmetricSecurityKey(key)
                };
                if (validAudience != null)
                {
                    parameters.ValidAudience = validAudience;
                    parameters.ValidateAudience = true;
                }
                else
                {
                    parameters.ValidateAudience = false;
                }
                //The default LifetimeValidator will have a grace period for tokens (5 minutes). Not suitable in our case
                parameters.LifetimeValidator = (notBefore, expires, testtoken, parameter) => {
                    if (expires != null && notBefore != null)
                    {
                        var now = DateTime.UtcNow;
                        if (expires.Value > now && notBefore < now) return true;
                    }
                    return false;
                };
                SecurityToken securityToken;
                ClaimsPrincipal principal = tokenHandler.ValidateToken(token,
                      parameters, out securityToken);
                return principal;
            }
            catch (Exception ex)
            {
                Debug.WriteLine("Error:" + ex.Message);
                return null;
            }
        }
    }
}
