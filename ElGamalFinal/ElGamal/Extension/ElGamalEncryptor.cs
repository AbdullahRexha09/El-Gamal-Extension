using ElGamal.Structs;
using System;
using System.Collections.Generic;
using System.Text;

namespace ElGamal.Models
{
    public class ElGamalEncryptor : ElGamalAbstractCipher
    {
        Random rndom;
        public ElGamalEncryptor(ElGamalKeyStruct p_struct) : base(p_struct)
        {
            rndom = new Random();
        }
        protected override byte[] ProcessDataBlock(byte[] block)
        {
            BigInteger K;
            do
            {
                K = new BigInteger();
                K.genRandomBits(keyStruct.P.bitCount() - 1, rndom);
            } while (K.gcd(keyStruct.P - 1) != 1);

            BigInteger A = keyStruct.G.modPow(K, keyStruct.P);
            BigInteger B = (keyStruct.Y.modPow(K, keyStruct.P)
                * new BigInteger(block)) % (keyStruct.P);

            byte[] result = new byte[cipherTextBlockSize];
            byte[] aBytes = A.getBytes();
            Array.Copy(aBytes, 0, result, cipherTextBlockSize / 2
                - aBytes.Length, aBytes.Length);
            byte[] bBytes = B.getBytes();
            Array.Copy(bBytes, 0, result, cipherTextBlockSize
                - bBytes.Length, bBytes.Length);
            return result;
        }
        protected override byte[] ProcessFinalDataBlock(byte[] finalBlock)
        {
            if (finalBlock.Length > 0)
            {
                if (finalBlock.Length < blockSize)
                {
                    byte[] xPadded = new byte[blockSize];
                    Array.Copy(finalBlock, 0, xPadded, 0, finalBlock.Length);
                    return ProcessDataBlock(xPadded);
                }
                else
                {
                    return ProcessDataBlock(finalBlock);
                }
            }
            else
            {
                return new byte[0];
            }
        }
    }
}

