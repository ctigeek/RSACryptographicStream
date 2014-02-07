using System;
using System.IO;
using System.Security.Cryptography;

// DISCLAIMER: This code is free to use but comes with NO WARRANTY or liability. Use at your own risk.
// Full license is here: https://github.com/ctigeek/RSACryptographicStream/blob/master/LICENSE

namespace RSACryptographicStream
{
    public abstract class RSACryptographicStreamBase : Stream
    {
        public const int AesBlockSize = 128;
        public const CipherMode AesMode = CipherMode.CBC;

        protected AesManaged aesManaged; //symetrical encryption
        protected ICryptoTransform aesTransformer;
        protected CryptoStream cryptoStream;
        protected long position { get; set; }
        protected bool started { get; set; }
        protected bool closed { get; set; }
        protected readonly Stream UnderlyingStream;
        protected readonly RSACryptoServiceProvider RSAkey;

        int _aesKeySize = 256;
        public int AesKeySize
        {
            get { return _aesKeySize; }
            set
            {
                if (started)
                {
                    throw new InvalidOperationException("You cannot change this value after data has been written to the stream.");
                }
                if (value != 128 && value != 192 && value != 256)
                {
                    throw new InvalidDataException("The AES standard specifies key size must be 128, 192, or 256.");
                }
                _aesKeySize = value;
            }
        }

        public RSACryptographicStreamBase(Stream underlyingStream, RSACryptoServiceProvider key)
        {
            this.UnderlyingStream = underlyingStream;
            this.RSAkey = key;
            position = 0;
            started = false;
            closed = false;
        }
        protected override void Dispose(bool disposing)
        {
            Close();
            aesTransformer.Dispose();
            aesManaged.Dispose();
            cryptoStream.Dispose();
            base.Dispose(disposing);
        }
        protected AesManaged CreateAesManaged()
        {
            this.aesManaged = new AesManaged()
            {
                BlockSize = AesBlockSize,
                KeySize = AesKeySize,
                Mode = AesMode
            };
            return aesManaged;
        }
        public override void Flush()
        {
            if (CanWrite && !cryptoStream.HasFlushedFinalBlock)
            {
                cryptoStream.FlushFinalBlock();
            }
        }
        public override void Close()
        {
            if (!closed)
            {
                Flush();
                closed = true;
                cryptoStream.Close(); //this will probably close the underlying stream....
                base.Close();
            }
        }
        public override bool CanSeek
        {
            get { return false; }
        }
        public override long Length
        {
            get { throw new NotSupportedException(); }
        }
        public override long Position
        {
            get
            {
                return position;
            }
            set
            {
                throw new NotSupportedException();
            }
        }
        public override bool CanRead
        {
            get { return false; }
        }
        public override bool CanWrite
        {
            get { return false; }
        }
        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }
        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }
        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }
        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        public static int GetInt32(Stream stream)
        {
            byte[] theInt = new byte[4];
            stream.Read(theInt, 0, 4);
            return BitConverter.ToInt32(theInt, 0);
        }
        public static void WriteInt32(Stream stream, int theInt)
        {
            var bytes = BitConverter.GetBytes(theInt);
            stream.Write(bytes, 0, bytes.Length);
        }
        public static byte[] GetBytes(Stream stream, int length)
        {
            byte[] readBytes = new byte[length];
            stream.Read(readBytes, 0, length);
            return readBytes;
        }
    }
}
