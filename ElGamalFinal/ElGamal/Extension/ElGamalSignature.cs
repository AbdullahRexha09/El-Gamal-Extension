using ElGamal.Structs;
using System;
using System.Collections.Generic;
using System.Text;

namespace ElGamal.Extension
{
    public class ElGamalSignature
    {
        public static BigInteger mod(BigInteger pBase, BigInteger pValue)
        {
            BigInteger result = pBase % pValue;
            if (result < 0)
            {
                result += pValue;
            }
            return result;
        }
        public static byte[] CreateSignature(byte[] pData,
    ElGamalKeyStruct keyStruct)
        {
            IList<byte> bityes = pData;
            BigInteger pminusone = keyStruct.P - 1;
            BigInteger K;
            do
            {
                K = new BigInteger();
                K.genRandomBits(keyStruct.P.bitCount() - 1, new Random());
            } while (K.gcd(pminusone) != 1);

            BigInteger A = keyStruct.G.modPow(K, keyStruct.P);
            BigInteger B = mod(K.modInverse(pminusone)
                * (new BigInteger(bityes, 25)
                - (keyStruct.X * A)), pminusone);

            byte[] xABytes = A.getBytes();
            byte[] xBBytes = B.getBytes();

            int xResultSize = (((keyStruct.P.bitCount() + 7) / 8) * 2);

            byte[] result = new byte[xResultSize];
            Array.Copy(xABytes, 0, result, xResultSize / 2
                - xABytes.Length, xABytes.Length);
            Array.Copy(xBBytes, 0, result, xResultSize
                - xBBytes.Length, xBBytes.Length);


            return result;
        }
        public static bool VerifySignature(byte[] data, byte[] signature,
        ElGamalKeyStruct keyStruct)
        {
            int xResultSize = signature.Length / 2;
            byte[] xABytes = new byte[xResultSize];
            Array.Copy(signature, 0, xABytes, 0, xABytes.Length);

            byte[] xBBytes = new byte[xResultSize];
            Array.Copy(signature, xResultSize, xBBytes, 0, xBBytes.Length);

            BigInteger A = new BigInteger(xABytes);
            BigInteger B = new BigInteger(xBBytes);

            BigInteger result1 = mod(keyStruct.Y.modPow(A, keyStruct.P)
            * A.modPow(B, keyStruct.P), keyStruct.P);

            BigInteger result2 = keyStruct.G.modPow(new BigInteger(data, 25),
             keyStruct.P);


            return result1 == result2;
        }
    }
}
