using ElGamal.Extension;
using ElGamal.Structs;
using System;
using System.Numerics;
using System.Security.Cryptography;

namespace ElGamal.Models
{
    public class ElGamalManaged : ElGamal
    {
        private ElGamalKeyStruct keyStruct;
        public ElGamalManaged()
        {
            // create the key struct
            keyStruct = new ElGamalKeyStruct();
            // set all of the big integers to zero
            keyStruct.P = new BigInteger(0);
            keyStruct.G = new BigInteger(0);
            keyStruct.Y = new BigInteger(0);
            keyStruct.X = new BigInteger(0);
            // set the default key size value
            KeySizeValue = 1024;
            // set the range of legal keys
            LegalKeySizesValue = new KeySizes[] { new KeySizes(384, 1088, 8) };

        }
        /// <summary>
        /// This method contains .Net framework methods that are specially added for generation of pseudo-
        /// prime numbers and random bits
        /// </summary>
        /// <param name="pKeyStrength"></param>
        private void CreateKeyPair(int pKeyStrength)
        {
            Random randomGenerator = new Random();

            keyStruct.P = BigInteger.genPseudoPrime(pKeyStrength,
                16, randomGenerator);

            keyStruct.X = new BigInteger();
            keyStruct.X.genRandomBits(pKeyStrength - 1, randomGenerator);
            keyStruct.G = new BigInteger();
            keyStruct.G.genRandomBits(pKeyStrength - 1, randomGenerator);

            keyStruct.Y = keyStruct.G.modPow(keyStruct.X, keyStruct.P);
        }
        private bool NeedToGenerateKey()
        {
            return keyStruct.P == 0 && keyStruct.G == 0 && keyStruct.Y == 0;
        }
        public ElGamalKeyStruct KeyStruct
        {
            get
            {
                if (NeedToGenerateKey())
                {
                    CreateKeyPair(KeySizeValue);
                }
                return keyStruct;
            }
            set
            {
                keyStruct = value;
            }
        }
        public override void ImportParameters(ElGamalParameters parameters)
        {
            keyStruct.P = new BigInteger(parameters.P);
            keyStruct.G = new BigInteger(parameters.G);
            keyStruct.Y = new BigInteger(parameters.Y);
            if (parameters.X != null && parameters.X.Length > 0)
            {
                keyStruct.X = new BigInteger(parameters.X);
            }
            KeySizeValue = keyStruct.P.bitCount();
        }
        public override ElGamalParameters ExportParameters(bool
            includePrivateParameter)
        {

            if (NeedToGenerateKey())
            {
                CreateKeyPair(KeySizeValue);
            }

            ElGamalParameters parameters = new ElGamalParameters();
            parameters.P = keyStruct.P.getBytes();
            parameters.G = keyStruct.G.getBytes();
            parameters.Y = keyStruct.Y.getBytes();

            if (includePrivateParameter)
            {
                parameters.X = keyStruct.X.getBytes();
            }
            else
            {
                parameters.X = new byte[1];
            }
            return parameters;
        }
        public override byte[] Sign(byte[] hashCode)
        {
            if (NeedToGenerateKey()) 
            {
                CreateKeyPair(KeySizeValue);
            }

            return ElGamalSignature.CreateSignature(hashCode, keyStruct);

        }

        public override bool VerifySignature(byte[] hashCode, byte[] signature)
        {
            if (NeedToGenerateKey()) 
            {
                CreateKeyPair(KeySizeValue);
            }
            return ElGamalSignature.VerifySignature(hashCode, signature, keyStruct);
        }
    }
}
