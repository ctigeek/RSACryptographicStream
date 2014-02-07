using System;
using System.IO;
using System.Security.Cryptography;

// DISCLAIMER: This code is free to use but comes with NO WARRANTY or liability. Use at your own risk.
// Full license is here: https://github.com/ctigeek/RSACryptographicStream/blob/master/LICENSE

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

        private void WriteHeaders()
        {
            if (!started)
            {
                CreateAesManaged();
                aesTransformer = aesManaged.CreateEncryptor();

                RSAPKCS1KeyExchangeFormatter keyFormatter = new RSAPKCS1KeyExchangeFormatter(RSAkey);
                byte[] keyEncrypted = keyFormatter.CreateKeyExchange(aesManaged.Key, aesManaged.GetType());

                WriteInt32(UnderlyingStream, keyEncrypted.Length);
                WriteInt32(UnderlyingStream, aesManaged.IV.Length);
                UnderlyingStream.Write(keyEncrypted, 0, keyEncrypted.Length);
                UnderlyingStream.Write(aesManaged.IV, 0, aesManaged.IV.Length);

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
            WriteHeaders();
            cryptoStream.Write(buffer, offset, count);
            position += count;
        }
    }
}
