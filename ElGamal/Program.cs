using ElGamal.Models;
using AlGamal = ElGamal.Models.ElGamal;
using System;
using System.Text;

namespace ElGamal
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] x_plaintext
           = Encoding.Default.GetBytes("Programming .NET Security");

            // Create an instance of the algorithm and generate some keys
            AlGamal x_alg = new ElGamalManaged();
            // set the key size - keep is small to speed up the tests
            x_alg.KeySize = 384;
            // extract and print the xml string (this will cause
            // a new key pair to be generated)
            string x_xml_string = x_alg.ToXmlString(true);
            Console.WriteLine("\n{0}\n", x_xml_string);

            // Test the basic encryption support
            AlGamal x_encrypt_alg = new ElGamalManaged();
            // set the keys - note that we export without the
            // private parameters since we are encrypting data
            x_encrypt_alg.FromXmlString(x_alg.ToXmlString(false));
            byte[] x_ciphertext = x_alg.EncryptData(x_plaintext);

            // create a new instance of the algorithm to decrypt
            AlGamal x_decrypt_alg = new ElGamalManaged();
            // set the keys - note that we export with the
            // private parameters since we are decrypting data
            x_decrypt_alg.FromXmlString(x_alg.ToXmlString(true));
            // restore the plaintext
            byte[] x_candidate_plaintext = x_decrypt_alg.DecryptData(x_ciphertext);

            Console.WriteLine("BASIC ENCRYPTION: {0}",
                CompareArrays(x_plaintext, x_candidate_plaintext));
        }
        private static bool CompareArrays(byte[] p_arr1, byte[] p_arr2)
        {
            for (int i = 0; i < p_arr1.Length; i++)
            {
                if (p_arr1[i] != p_arr2[i])
                {
                    return false;
                }
            }
            return true;
        }
    }
}
