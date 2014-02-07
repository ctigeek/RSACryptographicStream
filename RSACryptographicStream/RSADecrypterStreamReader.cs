using System;
using System.IO;
using System.Security.Cryptography;

// DISCLAIMER: This code is free to use but comes with NO WARRANTY or liability. Use at your own risk.

namespace RSACryptographicStream
{
    public class RSADecrypterStreamReader : RSACryptographicStreamBase
    {
        public RSADecrypterStreamReader(Stream source, RSACryptoServiceProvider privateKey)
            : base(source, privateKey)
        {
            if (!source.CanRead)
            {
                throw new ArgumentException("The source stream is not readable.");
            }
        }
        public override bool CanRead
        {
            get { return true; }
        }

        private void StartTheEngine()
        {
            if (!started)
            {
                AesKeySize = GetInt32(UnderlyingStream);
                int lenIV = GetInt32(UnderlyingStream);
                var encryptedKey = GetBytes(UnderlyingStream, AesKeySize);
                var IV = GetBytes(UnderlyingStream, lenIV);

                var decryptedKey = RSAkey.Decrypt(encryptedKey, false);
                CreateAesManaged();
                aesTransformer = aesManaged.CreateDecryptor(decryptedKey, IV);

                cryptoStream = new CryptoStream(UnderlyingStream, aesTransformer, CryptoStreamMode.Read);

                started = true;
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (closed)
            {
                throw new InvalidOperationException("The stream is already closed.");
            }
            StartTheEngine();
            var actuallyRead = cryptoStream.Read(buffer, offset, count);
            position += actuallyRead;
            return actuallyRead;
        }
    }
}
