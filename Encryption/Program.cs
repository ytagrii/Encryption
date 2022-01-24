using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace Encryption
{
    class Program
    {
        static void Main(string[] args)
        {
            DecryptPDF();


            // Our inputs in ASCII
            //string password = "drpepperissuperior";
            //string plaintext = "journeybeforedestination";

            //// calling our AES Encryption Method
            //byte[] cipherBytes = Encrypt(password, plaintext);

            //// Hexadecimal notation is easy to read, so we'll convert our byte array to hex for writing to the console.
            //// If we were saving this to file, we likely would not want to convert to hex.
            //string cipherHex = BitConverter.ToString(cipherBytes).Replace("-", ""); // This is a simple way to get a hex string from a byte[]

            //Console.WriteLine("PlainText: " + plaintext);
            //Console.WriteLine("CipherText with IV (Hex): " + cipherHex);

            //// Call our decryption method
            //string decryptedMessage = Decrypt(cipherBytes, password);
            //Console.WriteLine("Decrypted Message: " + decryptedMessage);
        }

        public static byte[] Encrypt(string password, string message)
        {
            // We need the inputs as byte[]. If we are reading from a binary file, we would change this to File.ReadAllBytes() or similar.
            byte[] passwordBytes = Encoding.ASCII.GetBytes(password);
            byte[] plaintextBytes = Encoding.ASCII.GetBytes(message);

            // Normally we would use a standard key derivation function (KDF) to take our password, apply entropy, and get us the correct length
            // Strangely, .NET Core doesn't have any quality KDFs implemented in the default libraries (e.g., Scrypt, PBKDF2, etc.)
            // We could use a third-party library, but in this instance we will simply hash our password with SHA256.
            // This is a reasonable compromise, but in a production environment we should use a proper KDF.
            byte[] key = SHA256.Create().ComputeHash(passwordBytes);

            // Let's create our AES algorithm instance and set some properties.
            using Aes aes = Aes.Create();
            // The System.Security.Cryptography built-in AES library sadly only supports ECB and CBC modes of encryption
            // Neither is great, but we'll use CBC here because it is less problematic.
            // Other encryption modes are supported by third-party libraries.
            aes.Mode = CipherMode.CBC;
            // Usually our messages aren't exactly aligned with our block size, so we want to use a standard padding. This should match on the decryption.
            aes.Padding = PaddingMode.PKCS7;

            // It is common to handle data using streams in .NET, Java, and many languages.
            // Here we'll use a MemoryStream (a stream that exists purely in memory).
            // If we were wanting to write to a file, we may want to use a filestream and specify an output file.
            using MemoryStream memStream = new MemoryStream();

            // AES requires an "initialization vector (IV)", sometimes called a "nonce" to provide additional randomness.
            // This can be specified or randomly generated.
            // It is customary to prepend our IV to our message or file. So we'll write it out at the beginning of our stream.
            memStream.Write(aes.IV);

            // So far, we haven't done any encrypting. We've just set everything up.
            // There is a special type of stream called a CryptoStream that allows us to read or write ciphertext.
            // Here we're going to create a CryptoStream with a new "Encryptor" because we're doing encryption here.
            // We're also going to give it our memorystream so we can send the encrypted information to our memory stream.
            using CryptoStream cryptostream = new CryptoStream(memStream, aes.CreateEncryptor(key, aes.IV), CryptoStreamMode.Write);

            // Write our message out to the cryptostream
            cryptostream.Write(plaintextBytes);
            cryptostream.FlushFinalBlock(); // This helps prevent padding errors on the final block.

            // Now we are going to take our MemoryStream and convert it to our final output.
            // If we wanted to write the data to a file, we might use a TextWriter (for ASCII files) or a BinaryWriter (for binary files)
            // Here we're going to output a string to the console. One option would be to use a StreamReader (especially if we were going straight to a string).
            // But we're going to return a byte[] so we can convert it later.
            byte[] cipherBytes = memStream.ToArray();

            return cipherBytes;
        }

        public static string Decrypt(byte[] cipherbytes, string password)
        {
            // Again, we need to convert (derive) our key from the string password.
            // We'll use a SHA256 hash again for this
            byte[] key = SHA256.Create().ComputeHash(Encoding.ASCII.GetBytes(password));

            // Let's read our bytes into a memory stream. If we were decrypting a file, we would probably use a Filestream
            using MemoryStream memStream = new MemoryStream(cipherbytes);

            // Create our instance of the AES algorithm and set its properties
            using Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC; // Match the encryption mode with the encrypt method
            aes.Padding = PaddingMode.PKCS7; // Again, match the padding type with the encrypt method

            // In this case, we need to get the IV that was prepended to our encrypted data
            byte[] iv = new byte[aes.IV.Length]; // create an array of the proper length (default IV length is what we want)
            memStream.Read(iv, 0, iv.Length); // read the IV from the beginning of our memory stream and populate our iv byte[]

            // We'll create a new cryptostream, this time with a Decryptor and in read mode
            using CryptoStream cryptStream = new CryptoStream(memStream, aes.CreateDecryptor(key, iv), CryptoStreamMode.Read);

            // We're going to read the decrypted information from the cryptostream using a streamreader
            StreamReader streamReader = new StreamReader(cryptStream);
            string decryptedText = streamReader.ReadToEnd(); // Read all the way to the end and output as a string

            return decryptedText;
        }

        /// <summary>
        /// This helper method from https://stackoverflow.com/questions/311165/how-do-you-convert-a-byte-array-to-a-hexadecimal-string-and-vice-versa takes the pain out of 
        /// manually converting hex strings to byte arrays
        /// </summary>
        /// <param name="hex">The input hex string</param>
        /// <returns>The hex string as a Byte[]</returns>
        public static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        /// <summary>
        /// Helper method to read all bytes from a reader into an array
        /// </summary>
        /// <param name="reader"></param>
        /// <returns></returns>
        public static byte[] ReadAllBytes(BinaryReader reader)
        {
            const int bufferSize = 4096;
            using (var ms = new MemoryStream())
            {
                byte[] buffer = new byte[bufferSize];
                int count;
                while ((count = reader.Read(buffer, 0, buffer.Length)) != 0)
                    ms.Write(buffer, 0, count);
                return ms.ToArray();
            }
        }


        public static void DecryptPDF()
        {
            string password = "drpepperissuperior";
            string fileName = "/Users/ryanward/Desktop/Encryption and Hashing Lab Files/PO-encrypted.pdf";
            // Again, we need to convert (derive) our key from the string password.
            // We'll use a SHA256 hash again for this
            byte[] key = SHA256.Create().ComputeHash(Encoding.ASCII.GetBytes(password));

            // Let's read our bytes into a memory stream. If we were decrypting a file, we would probably use a Filestream
            //using MemoryStream memStream = new MemoryStream(cipherbytes);
            using FileStream sf = new FileStream(fileName, FileMode.Open, FileAccess.Read);

            // Create our instance of the AES algorithm and set its properties
            using Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC; // Match the encryption mode with the encrypt method
            aes.Padding = PaddingMode.PKCS7; // Again, match the padding type with the encrypt method

            // In this case, we need to get the IV that was prepended to our encrypted data
            byte[] iv = new byte[aes.IV.Length]; // create an array of the proper length (default IV length is what we want)
            sf.Read(iv, 0, iv.Length); // read the IV from the beginning of our memory stream and populate our iv byte[]

            // We'll create a new cryptostream, this time with a Decryptor and in read mode
            using CryptoStream cryptStream = new CryptoStream(sf, aes.CreateDecryptor(key, iv), CryptoStreamMode.Read);

            // We're going to read the decrypted information from the cryptostream using a streamreader
            //StreamReader streamReader = new StreamReader(cryptStream);
            //string decryptedText = streamReader.ReadToEnd(); // Read all the way to the end and output as a string

            BinaryReader reader = new BinaryReader(cryptStream);
            byte[] allBytes = ReadAllBytes(reader);

            string filePathNew = "/Users/ryanward/Desktop/Encryption and Hashing Lab Files/PO-decrypted.pdf";
            File.WriteAllBytes(filePathNew, allBytes);

            //return decryptedText;
        }
    }
}