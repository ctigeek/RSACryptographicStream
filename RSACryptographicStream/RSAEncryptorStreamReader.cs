using System;
using System.IO;
using System.Security.Cryptography;

// DISCLAIMER: This code is free to use but comes with NO WARRANTY or liability. Use at your own risk.
// Full license is here: https://github.com/ctigeek/RSACryptographicStream/blob/master/LICENSE

namespace RSACryptographicStream
{
    public class RSAEncryptorStreamReader : RSACryptographicStreamBase
    {
        private byte[] header;

        public RSAEncryptorStreamReader(Stream source, RSACryptoServiceProvider publicKey)
            : base(source, publicKey)
        {
            if (!source.CanRead)
            {
                throw new ArgumentException("The source stream is not readable.");
            }

            CreateAesManaged();
            aesTransformer = aesManaged.CreateEncryptor();

            RSAPKCS1KeyExchangeFormatter keyFormatter = new RSAPKCS1KeyExchangeFormatter(RSAkey);
            byte[] keyEncrypted = keyFormatter.CreateKeyExchange(aesManaged.Key, aesManaged.GetType());

            var keyEncryptedLengthBytes = BitConverter.GetBytes(keyEncrypted.Length);
            var aesManagedIVLengthBytes = BitConverter.GetBytes(aesManaged.IV.Length);
            var totalBytesInHeader = keyEncryptedLengthBytes.Length
                                + aesManagedIVLengthBytes.Length
                                + keyEncrypted.Length
                                + aesManaged.IV.Length;
            header = new byte[totalBytesInHeader];

            int offset = 0;
            System.Buffer.BlockCopy(keyEncryptedLengthBytes, 0, header, offset, keyEncryptedLengthBytes.Length);
            offset += keyEncryptedLengthBytes.Length;
            System.Buffer.BlockCopy(aesManagedIVLengthBytes, 0, header, offset, aesManagedIVLengthBytes.Length);
            offset += aesManagedIVLengthBytes.Length;
            System.Buffer.BlockCopy(keyEncrypted, 0, header, offset, keyEncrypted.Length);
            offset += keyEncrypted.Length;
            System.Buffer.BlockCopy(aesManaged.IV, 0, header, offset, aesManaged.IV.Length);
            offset += aesManaged.IV.Length;

            cryptoStream = new CryptoStream(UnderlyingStream, aesTransformer, CryptoStreamMode.Read);
        }

        public override bool CanRead
        {
            get { return true; }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (closed)
            {
                throw new InvalidOperationException("The stream is already closed.");
            }
            int currentOffset = offset;
            int writeHeaderCount = 0;
            if (position < header.Length)
            {
                int headerRemainingCount = header.Length - (int)position;
                writeHeaderCount = (headerRemainingCount < count) ? headerRemainingCount : count;
                System.Buffer.BlockCopy(header, (int)position, buffer, currentOffset, writeHeaderCount);
                currentOffset += writeHeaderCount;
            }

            var actuallyRead = writeHeaderCount + cryptoStream.Read(buffer, currentOffset, count - writeHeaderCount);
            position += actuallyRead;
            return actuallyRead;
        }
    }
}
