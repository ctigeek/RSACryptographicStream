using System;
using System.IO;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace RSACryptographicStream
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                //This creates the RSA keys. In a production environment, you'll probably be using key files.
                // One of the advantages of using RSA is you can have the public key used for encryption on your web servers, and keep the private key safe somewhere that's not on a public-facing server.
                var rsaProvider = new RSACryptoServiceProvider();

                //create a stream with test data....
                string testData = "some random string.";
                MemoryStream source = new MemoryStream();
                StreamWriter writer = new StreamWriter(source);
                writer.AutoFlush = true;
                writer.Write(testData);

                source.Seek(0, SeekOrigin.Begin);

                //Encrypt the stream....
                var encryptedData = new MemoryStream();
                var encryptor = new RSAEncryptorStreamWriter(encryptedData, rsaProvider);
                source.CopyTo(encryptor);
                encryptor.Flush(); // Important! You must flush or dispose any stream writer ...the underlying stream will not have the last chunk of data until that happens!

                encryptedData.Seek(0, SeekOrigin.Begin);

                //decrypt to a new stream...
                var decryptedData = new MemoryStream();
                var decryptor = new RSADecrypterStreamReader(encryptedData, rsaProvider);
                decryptor.CopyTo(decryptedData);
                decryptedData.Flush();
                decryptedData.Seek(0, SeekOrigin.Begin);
                
                //read into a string...
                StreamReader reader = new StreamReader(decryptedData);
                var decryptedString = reader.ReadToEnd();

                Console.WriteLine("Original string:{0}", testData);
                Console.WriteLine("Decrypted string:{0}", decryptedString);

                //Yes, I know I'm not disposing properly... it's just test code...
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
            Console.WriteLine("Press enter to close.");
            Console.ReadLine();
        }
    }
}
