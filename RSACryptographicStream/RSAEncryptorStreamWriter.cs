using System;
using System.IO;
using System.Security.Cryptography;

// DISCLAIMER: This code is free to use but comes with NO WARRANTY or liability. Use at your own risk.

namespace RSACryptographicStream
{
    public class RSAEncryptorStreamWriter : RSACryptographicStreamBase
    {
        public RSAEncryptorStreamWriter(Stream destination, RSACryptoServiceProvider publicKey)
            : base(destination, publicKey)
        {
            if (!destination.CanWrite)
            {
                throw new ArgumentException("The destination stream is writable.");
            }
        }

        public override bool CanWrite
        {
            get { return true; }
        }

        private void StartTheEngine()
        {
            if (!started)
            {
                CreateAesManaged();
                aesTransformer = aesManaged.CreateEncryptor();

                RSAPKCS1KeyExchangeFormatter keyFormatter = new RSAPKCS1KeyExchangeFormatter(RSAkey);
                byte[] keyEncrypted = keyFormatter.CreateKeyExchange(aesManaged.Key, aesManaged.GetType());

                byte[] LenK = new byte[4];
                byte[] LenIV = new byte[4];

                int lKey = keyEncrypted.Length;
                LenK = BitConverter.GetBytes(lKey);
                int lIV = aesManaged.IV.Length;
                LenIV = BitConverter.GetBytes(lIV);

                UnderlyingStream.Write(LenK, 0, 4);
                UnderlyingStream.Write(LenIV, 0, 4);
                UnderlyingStream.Write(keyEncrypted, 0, lKey);
                UnderlyingStream.Write(aesManaged.IV, 0, lIV);

                cryptoStream = new CryptoStream(UnderlyingStream, aesTransformer, CryptoStreamMode.Write);

                started = true;
            }
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (closed)
            {
                throw new InvalidOperationException("The stream is already closed.");
            }
            StartTheEngine();
            cryptoStream.Write(buffer, offset, count);
            position += count;
        }
    }
}
