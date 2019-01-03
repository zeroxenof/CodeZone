using Jose;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Security.Cryptography;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace JWTDemo
{
    class Program
    {

        private static CngKey GetPrivateKey(string p8File)
        {
            using (var reader = File.OpenText(p8File))
            {
                var ecPrivateKeyParameters = (ECPrivateKeyParameters)new PemReader(reader).ReadObject();
                var x = ecPrivateKeyParameters.Parameters.G.AffineXCoord.GetEncoded();
                var y = ecPrivateKeyParameters.Parameters.G.AffineYCoord.GetEncoded();
                var d = ecPrivateKeyParameters.D.ToByteArrayUnsigned();
                return EccKey.New(x, y, d);
            }
        }
        static void Main(string[] args)
        {
            string p8File = @"your p8 file";
            var keyId = "your key id";
            var teamId = "your team id";
            var exp = DateTimeOffset.UtcNow.AddMonths(6).ToUnixTimeSeconds();
            var iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();



            var payload = new Dictionary<string, object>
            {
                { "iss", teamId },
                { "exp", exp },
                { "iat", iat}
            };
            var header = new Dictionary<string, object>
            {

                { "kid", keyId},
                { "alg","ES256"}

            };
            var privateKey = GetPrivateKey(p8File);
            string token = Jose.JWT.Encode(payload, privateKey, JwsAlgorithm.ES256, header);
            var url = "https://api.music.apple.com/v1/catalog/us/artists/1798556";
            Console.WriteLine(token);

            using (WebClient wc = new WebClient())
            {
                string URI = url;
                wc.Headers.Add("Content-Type", "text");
                wc.Headers[HttpRequestHeader.Authorization] = $"Bearer {token}";
                string HtmlResult = wc.DownloadString(URI);
                Console.WriteLine(HtmlResult);
            }
            Console.Read();
        }
    }
}
