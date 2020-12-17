using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace JwkGenerator
{
    public class JsonWebKeyDto
    {
        public JsonWebKeyDto(X509Certificate2 certificate)
        {
            Kid = certificate.Thumbprint;
            X5t = Base64UrlEncoder.Encode(certificate.GetCertHash());
            X5c = new[] { Convert.ToBase64String(certificate.RawData) };
            Use = "sig";

            AsymmetricAlgorithm key = null;
            var privateKeyIsExportable = false;
            try
            {
                if (certificate.HasPrivateKey)
                {
                    key = certificate.PrivateKey;
                    privateKeyIsExportable = true;
                }
            }
            catch { }
            if (key == null)
            {
                key = certificate.PublicKey.Key;
            }

            if (key is RSA rsa)
            {
                Kty = JsonWebAlgorithmsKeyTypes.RSA;

                var parameters = rsa.ExportParameters(privateKeyIsExportable);

                E = Base64UrlEncoder.Encode(parameters.Exponent);
                N = Base64UrlEncoder.Encode(parameters.Modulus);
                if (privateKeyIsExportable)
                {
                    D = Base64UrlEncoder.Encode(parameters.D);
                    DP = Base64UrlEncoder.Encode(parameters.DP);
                    DQ = Base64UrlEncoder.Encode(parameters.DQ);
                    P = Base64UrlEncoder.Encode(parameters.P);
                    Q = Base64UrlEncoder.Encode(parameters.Q);
                    QI = Base64UrlEncoder.Encode(parameters.InverseQ);
                }
            }
            else if ((certificate.PrivateKey ?? certificate.PublicKey.Key) is ECDsa ecdsa)
            {
                Kty = JsonWebAlgorithmsKeyTypes.EllipticCurve;

                var parameters = ecdsa.ExportParameters(privateKeyIsExportable);
                X = Base64UrlEncoder.Encode(parameters.Q.X);
                Y = Base64UrlEncoder.Encode(parameters.Q.Y);
                Crv = parameters.Curve.Oid.Value switch
                {
                    "1.2.840.10045.3.1.7" => JsonWebKeyECTypes.P256,
                    "1.3.132.0.34" => JsonWebKeyECTypes.P384,
                    "1.3.132.0.35" => JsonWebKeyECTypes.P521,
                    _ => throw new InvalidOperationException($"Unsupported curve type of {parameters.Curve.Oid.Value} - {parameters.Curve.Oid.FriendlyName}"),
                };
                if (privateKeyIsExportable)
                {
                    D = Base64UrlEncoder.Encode(parameters.D);
                }
            }
            else
            {
                throw new InvalidOperationException($"key type: {(certificate.PrivateKey ?? certificate.PublicKey.Key).GetType().Name} not supported.");
            }
            Alg = certificate.SignatureAlgorithm.Value switch
            {
                "1.2.840.113549.1.1.11" => SecurityAlgorithms.RsaSha256,
                "1.2.840.113549.1.1.12" => SecurityAlgorithms.RsaSha384,
                "1.2.840.113549.1.1.13" => SecurityAlgorithms.RsaSha256,
                "1.2.840.10045.4.3.2" => SecurityAlgorithms.EcdsaSha256,
                "1.2.840.10045.4.3.3" => SecurityAlgorithms.EcdsaSha384,
                "1.2.840.10045.4.3.4" => SecurityAlgorithms.EcdsaSha512,
                _ => throw new InvalidOperationException($"Unsupported algorithm of {certificate.SignatureAlgorithm.Value} - {certificate.SignatureAlgorithm.FriendlyName}"),
            };
        }

        public IList<string> KeyOps { get; set; } = new List<string>();
        public string Y { get; set; }
        public string X5u { get; set; }
        public string X5tS256 { get; set; }
        public string X5t { get; set; }
        public IList<string> X5c { get; set; } = new List<string>();
        public string X { get; set; }
        public string Use { get; set; }
        public string QI { get; set; }
        public string Q { get; set; }
        public string P { get; set; }
        public IList<string> Oth { get; set; } = new List<string>();
        public string N { get; set; }
        public string Kty { get; set; }
        public string K { get; set; }
        public string E { get; set; }
        public string DQ { get; set; }
        public string DP { get; set; }
        public string D { get; set; }
        public string Crv { get; set; }
        public string Alg { get; set; }
        public IDictionary<string, object> AdditionalData { get; set; } = new Dictionary<string, object>();
        public string Kid { get; set; }


        public bool HasPrivateKey
        {
            get
            {
                if (Kty == JsonWebAlgorithmsKeyTypes.RSA)
                    return D != null && DP != null && DQ != null && P != null && Q != null && QI != null;
                else if (Kty == JsonWebAlgorithmsKeyTypes.EllipticCurve)
                    return D != null;
                else
                    return false;
            }
        }
        public int KeySize
        {
            get
            {
                if (Kty == JsonWebAlgorithmsKeyTypes.RSA && !string.IsNullOrEmpty(N))
                    return Base64UrlEncoder.DecodeBytes(N).Length * 8;
                else if (Kty == JsonWebAlgorithmsKeyTypes.EllipticCurve && !string.IsNullOrEmpty(X))
                    return Base64UrlEncoder.DecodeBytes(X).Length * 8;
                else if (Kty == JsonWebAlgorithmsKeyTypes.Octet && !string.IsNullOrEmpty(K))
                    return Base64UrlEncoder.DecodeBytes(K).Length * 8;
                else
                    return 0;
            }
        }
    }
}
