using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using System.Text.Json.Nodes;
using Amazon.Lambda.Core;
using JWT;
using JWT.Algorithms;
using JWT.Exceptions;
using JWT.Serializers;
using Microsoft.IdentityModel.Tokens;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace JWTLambda;

public class Function
{

    /// <summary>
    /// A simple function that takes a string and does a ToUpper
    /// </summary>
    /// <param name="input"></param>
    /// <param name="context"></param>
    /// <returns></returns>
    public string FunctionHandler(Request Request, ILambdaContext context)
    {
        var t = ConvertJwtStringToJwtSecurityToken(Request.Token);

        string jsonToken = JsonSerializer.Serialize(t);

        return jsonToken;
    }

    public static JwtSecurityToken ConvertJwtStringToJwtSecurityToken(string? jwt)
    {
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(jwt);

        HttpClient httpClient = new HttpClient();

        string url = token.Issuer + "/.well-known/openid-configuration";

        var httpR = httpClient.GetStringAsync(url);

        string rr = httpR.Result;

        // fetch jwk_uri
        var parsedKey = JsonNode.Parse(rr);

        string jwksUrl = parsedKey["jwks_uri"].GetValue<string>();

        var jwks = httpClient.GetStringAsync(jwksUrl).Result;

        var jsonWebKeys = new JsonWebKeySet(jwks);

        // https://www.scottbrady91.com/c-sharp/rsa-key-loading-dotnet

        // https://stackoverflow.com/questions/40623346/how-do-i-validate-a-jwt-using-jwtsecuritytokenhandler-and-a-jwks-endpoint

        handler.ValidateToken(jwt, new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            ValidateIssuer = false,
            ValidateAudience = false,
            IssuerSigningKeys = jsonWebKeys.GetSigningKeys(),
            // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
            ClockSkew = TimeSpan.Zero
        }, out SecurityToken validatedToken);

        return token;
    }
}
