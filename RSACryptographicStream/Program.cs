using System;
using System.IO;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Linq;

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
                var rsaKey = new RSACryptoServiceProvider();
                RSACryptoServiceProvider publicKey = rsaKey;
                RSACryptoServiceProvider privateKey = rsaKey;

                //Or you can load in a certifacte.... See the MSDN article on x509certificates on how to implement this method....
                //var cert = GetCertificateFromStore("CN=FileEncryptionTest2");
                //RSACryptoServiceProvider publicKey = (RSACryptoServiceProvider)cert.PublicKey.Key;
                //RSACryptoServiceProvider privateKey = (RSACryptoServiceProvider)cert.PrivateKey;

                string encryptThisString = GetString(2000);
                Stream source = Streamify(encryptThisString);
                                
                //Encrypt the stream....
                var destination = new MemoryStream();

                //Magic!
                //EncryptUsingReader(source, destination, publicKey);
                //OR
                EncryptUsingWriter(source, destination, publicKey);

                destination.Seek(0, SeekOrigin.Begin);
                //decrypt to a new stream...
                var decryptedData = new MemoryStream();


                //more Magic!
                //DecryptUsingReader(destination, decryptedData, privateKey);
                //OR
                DecryptUsingWriter(destination, decryptedData, privateKey);

                //Turn back into a string....
                decryptedData.Seek(0, SeekOrigin.Begin);
                string decryptedString = Stringify(decryptedData);

                //Console.WriteLine("Original string:{0}", encryptThisString);
                //Console.WriteLine("Decrypted string:{0}", decryptedString);

                if (encryptThisString == decryptedString)
                {
                    Console.WriteLine("Hooray, they match.");
                }
                //Yes, I know I'm not disposing properly... it's just test code...
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
            Console.WriteLine("Press enter to close.");
            Console.ReadLine();
        }

        private static void EncryptUsingWriter(Stream source, Stream destination, RSACryptoServiceProvider key)
        {
            var encryptor = new RSAEncryptorStreamWriter(destination, key);
            source.CopyTo(encryptor);
            encryptor.Flush(); // Important! You must flush or dispose any stream writer ...the underlying stream will not have the last chunk of data until that happens!
        }
        private static void EncryptUsingReader(Stream source, Stream destination, RSACryptoServiceProvider key)
        {
            var encryptor = new RSAEncryptorStreamReader(source, key);
            encryptor.CopyTo(destination);
            encryptor.Flush();
        }

        private static void DecryptUsingReader(Stream source, Stream destination, RSACryptoServiceProvider key)
        {
            var decryptor = new RSADecrypterStreamReader(source, key);
            decryptor.CopyTo(destination);
            decryptor.Flush();
        }
        private static void DecryptUsingWriter(Stream source, Stream destination, RSACryptoServiceProvider key)
        {
            var decryptor = new RSADecrypterStreamWriter(destination, key);
            source.CopyTo(decryptor);
            decryptor.Flush();
        }

        const string LoremIpsum = @"Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
        private static string GetString(int numOfCharacters)
        {
            int count = (numOfCharacters / LoremIpsum.Length) + 1;
            string testData = String.Join(Environment.NewLine, Enumerable.Repeat(LoremIpsum, count));
            return testData;
        }
        private static Stream Streamify(string str)
        {
            //create a stream with test data....
            MemoryStream source = new MemoryStream();
            StreamWriter writer = new StreamWriter(source);
            writer.AutoFlush = true;
            writer.Write(str);

            source.Seek(0, SeekOrigin.Begin);
            return source;
        }
        private static string Stringify(Stream stream)
        {
            StreamReader reader = new StreamReader(stream);
            return reader.ReadToEnd();
        }
    }
}
