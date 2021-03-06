using ElGamal.Structs;
using System;
using System.Numerics;
using System.Security.Cryptography;

namespace ElGamal.Models
{
    public class ElGamalManaged : ElGamal
    {
        private ElGamalKeyStruct o_key_struct;
        public ElGamalManaged()
        {
            // create the key struct
            o_key_struct = new ElGamalKeyStruct();
            // set all of the big integers to zero
            o_key_struct.P = new BigInteger(0);
            o_key_struct.G = new BigInteger(0);
            o_key_struct.Y = new BigInteger(0);
            o_key_struct.X = new BigInteger(0);
            // set the default key size value
            KeySizeValue = 1024;
            // set the range of legal keys
            LegalKeySizesValue = new KeySizes[] { new KeySizes(384, 1088, 8) };

        }
        public override string SignatureAlgorithm
        {
            get
            {
                return "ElGamal";
            }
        }
        public override string KeyExchangeAlgorithm
        {
            get
            {
                return "ElGamal";
            }
        }
        /// <summary>
        /// This method contains .Net framework methods that are specially added for generation of pseudo-
        /// prime numbers and random bits
        /// </summary>
        /// <param name="p_key_strength"></param>
        private void CreateKeyPair(int p_key_strength)
        {
            // create the random number generator
            Random x_random_generator = new Random();

            // create the large prime number, P
            o_key_struct.P = BigInteger.genPseudoPrime(p_key_strength,
                16, x_random_generator);

            // create the two random numbers, which are smaller than P
            o_key_struct.X = new BigInteger();
            o_key_struct.X.genRandomBits(p_key_strength - 1, x_random_generator);
            o_key_struct.G = new BigInteger();
            o_key_struct.G.genRandomBits(p_key_strength - 1, x_random_generator);

            // compute Y
            o_key_struct.Y = o_key_struct.G.modPow(o_key_struct.X, o_key_struct.P);
        }
        private bool NeedToGenerateKey()
        {
            return o_key_struct.P == 0 && o_key_struct.G == 0 && o_key_struct.Y == 0;
        }
        public ElGamalKeyStruct KeyStruct
        {
            get
            {
                if (NeedToGenerateKey())
                {
                    CreateKeyPair(KeySizeValue);
                }
                return o_key_struct;
            }
            set
            {
                o_key_struct = value;
            }
        }
        public override void ImportParameters(ElGamalParameters p_parameters)
        {
            // obtain the  big integer values from the byte parameter values
            o_key_struct.P = new BigInteger(p_parameters.P);
            o_key_struct.G = new BigInteger(p_parameters.G);
            o_key_struct.Y = new BigInteger(p_parameters.Y);
            if (p_parameters.X != null && p_parameters.X.Length > 0)
            {
                o_key_struct.X = new BigInteger(p_parameters.X);
            }
            // set the length of the key based on the import
            KeySizeValue = o_key_struct.P.bitCount();
        }

        public override byte[] DecryptData(byte[] p_data)
        {
            if (NeedToGenerateKey())
            {
                // we need to create a new key before we can export 
                CreateKeyPair(KeySizeValue);
            }
            // encrypt the data
            ElGamalDecryptor x_enc = new ElGamalDecryptor(o_key_struct);
            return x_enc.ProcessData(p_data);
        }

        public override byte[] EncryptData(byte[] p_data)
        {
            if (NeedToGenerateKey())
            {
                // we need to create a new key before we can export 
                CreateKeyPair(KeySizeValue);
            }
            // encrypt the data
            ElGamalEncryptor x_enc = new ElGamalEncryptor(o_key_struct);
            return x_enc.ProcessData(p_data);
        }


        public override ElGamalParameters ExportParameters(bool
            p_include_private_params)
        {

            if (NeedToGenerateKey())
            {
                // we need to create a new key before we can export 
                CreateKeyPair(KeySizeValue);
            }

            // create the parameter set
            ElGamalParameters x_params = new ElGamalParameters();
            // set the public values of the parameters
            x_params.P = o_key_struct.P.getBytes();
            x_params.G = o_key_struct.G.getBytes();
            x_params.Y = o_key_struct.Y.getBytes();

            // if required, include the private value, X
            if (p_include_private_params)
            {
                x_params.X = o_key_struct.X.getBytes();
            }
            else
            {
                // ensure that we zero the value
                x_params.X = new byte[1];
            }
            // return the parameter set
            return x_params;
        }
        protected override void Dispose(bool p_bool)
        {
            // do nothing - no unmanaged resources to release
        }

        public override byte[] Sign(byte[] p_hashcode)
        {
            throw new System.NotImplementedException();
        }

        public override bool VerifySignature(byte[] p_hashcode, byte[] p_signature)
        {
            throw new System.NotImplementedException();
        }
    }
}
