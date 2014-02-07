RSACryptographicStream
======================

Stream classes for encryption/decryption using AES with an RSA wrapper.

This will encrypt the stream using AES, but encrypts the AES key using RSA and writes it to head of the stream.
A new AES key is generated each time.
The RSA key can be stored in an X509 certificate and kept in a key store.
For code examples of how to read in an X509 certificate and pass it in the constructor, see the method *GetCertificateFromStore* in the code examples on MSDN:
http://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x509certificate2(v=vs.110).aspx

