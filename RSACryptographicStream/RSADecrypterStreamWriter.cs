using System;
using System.IO;
using System.Security.Cryptography;

// DISCLAIMER: This code is free to use but comes with NO WARRANTY or liability. Use at your own risk.
// Full license is here: https://github.com/ctigeek/RSACryptographicStream/blob/master/LICENSE

namespace RSACryptographicStream
{
    public class RSADecrypterStreamWriter : RSACryptographicStreamBase
    {
        byte[] header;

        public RSADecrypterStreamWriter(Stream destination, RSACryptoServiceProvider privateKey)
            : base(destination, privateKey)
        {
            if (!destination.CanWrite)
            {
                throw new ArgumentException("The destination stream is not writable.");
            }
        }

        public override bool CanWrite
        {
            get { return true; }
        }

        private int ReadHeaders(byte[] buffer, int offset, int count)
        {
            if (!started)
            {
                int localOffset = 0;
                AesKeySize = BitConverter.ToInt32(buffer, offset);
                localOffset += 4;
                int lenIV = BitConverter.ToInt32(buffer, offset + localOffset);
                localOffset += 4;
                int totalHeaderSize = AesKeySize + lenIV + localOffset;
                if (count < totalHeaderSize)
                {
                    throw new ApplicationException("Unable to read header from buffer. You must pass at least " + totalHeaderSize.ToString() + " bytes in the buffer so the encryption header can be read.");
                }
                var encryptedKey = new byte[AesKeySize];
                Buffer.BlockCopy(buffer, offset + localOffset, encryptedKey, 0, AesKeySize);
                localOffset += AesKeySize;

                var IV = new byte[lenIV];
                Buffer.BlockCopy(buffer, offset + localOffset, IV, 0, lenIV);
                localOffset += lenIV;

                var decryptedKey = RSAkey.Decrypt(encryptedKey, false);
                CreateAesManaged();
                aesTransformer = aesManaged.CreateDecryptor(decryptedKey, IV);

                cryptoStream = new CryptoStream(UnderlyingStream, aesTransformer, CryptoStreamMode.Write);

                started = true;
                return localOffset;
            }
            return 0;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (closed)
            {
                throw new InvalidOperationException("The stream is already closed.");
            }
            var localOffset = ReadHeaders(buffer, offset, count);
            cryptoStream.Write(buffer, localOffset, count - localOffset);
            position += count;
        }
    }
}
