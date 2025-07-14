using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace RbxSigChecker
{
    internal class Program
    {
        const string _rbxKeyB64 = "BgIAAACkAABSU0ExAAQAAAEAAQCjbUyx9OXTBcWEAonZOfAoT7YhMS+L21WwAZlsEjvzHXQpulpasNFhC1U6tBX6c8Qey2fiRBXHpqbh7vAC7u2niT6dMLLqY9UzII0jyxKD/EUODcQHTKpbM18FRobqLcvK0DNdIaHwypr7NRnSWk4NXhtM0v40W7/mr35PxbJ8rQ==";

        static readonly RSACryptoServiceProvider _rsaProvider = new();
        static readonly SHA1 _sha1Provider = SHA1.Create();

        static bool Verify(string document, byte[] signature)
            => _rsaProvider.VerifyHash(_sha1Provider.ComputeHash(Encoding.UTF8.GetBytes(document)), CryptoConfig.MapNameToOID("SHA1")!, signature);

        static void Main(string[] args)
        {
            string? filePath = args.ElementAtOrDefault(0);

            if (string.IsNullOrEmpty(filePath))
            {
                Console.WriteLine("Usage: RbxSigChecker.exe <filepath>");
                return;
            }

            if (!File.Exists(filePath))
            {
                Console.WriteLine($"The path {Path.GetFullPath(filePath)} does not exist");
                return;
            }

            string body = File.ReadAllText(filePath);
            var match = Regex.Match(body, "^(?:--rbxsig|)%([^%]+)%");

            if (!match.Success)
            {
                Console.WriteLine("Could not find signature. Ensure there are no newlines at the start of the file.");
                return;
            }
            
            _rsaProvider.ImportCspBlob(Convert.FromBase64String(_rbxKeyB64));

            string signatureB64 = match.Groups[1].Value;
            string document = body.Substring(body.IndexOf(signatureB64) + signatureB64.Length + 1);
            bool isCRLF = document.Contains("\r\n");

            if (!isCRLF)
                Console.WriteLine("Warning: Document is not fully CRLF");

            // ¯\_(ツ)_/¯
            switch (signatureB64.Length % 4)
            {
                case 1: signatureB64 = signatureB64[..^1]; break;
                case 2: signatureB64 += "=="; break;
                case 3: signatureB64 += "="; break;
            }

            byte[] signature = Convert.FromBase64String(signatureB64);

            if (Verify(document, signature))
            {
                Console.WriteLine("Signature is valid");
                return;
            }
            else
            {
                Console.WriteLine("Signature is not valid");
            }

            if (!isCRLF)
            {
                document = document.Replace("\n", "\r\n");

                if (Verify(document, signature))
                {
                    Console.WriteLine("Signature is valid if document is normalised to CRLF");
                    return;
                }
            }

            if (document.StartsWith("\r\n") && Verify(document.Substring(2), signature))
            {
                Console.WriteLine("Signature is valid if first newline is removed");
                return;
            }

            string documentAddCRLF = document;
            for (int i = 1; i <= 10; i++)
            {
                documentAddCRLF += "\r\n";

                if (Verify(documentAddCRLF, signature))
                {
                    Console.WriteLine($"Signature is valid if {i} newlines are appended to the document");
                    return;
                }
            }

            string documentDelCRLF = document;
            int count = 0;
            while (documentDelCRLF.EndsWith("\r\n"))
            {
                documentDelCRLF = documentDelCRLF[..^2];
                count++;

                if (Verify(documentDelCRLF, signature))
                {
                    Console.WriteLine($"Signature is valid if {count} newlines are removed from the end of the document");
                    return;
                }
            }

            return;
        }
    }
}