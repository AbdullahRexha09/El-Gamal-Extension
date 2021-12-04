using ElGamal.Structs;
using System;
using System.Collections.Generic;
using System.Text;

namespace ElGamal.Models
{
    public class ElGamalDecryptor : ElGamalAbstractCipher
    {
        public ElGamalDecryptor(ElGamalKeyStruct p_struct) : base(p_struct)
        {
            blockSize = cipherTextBlockSize;
        }
        protected override byte[] ProcessDataBlock(byte[] block)
        {
            byte[] aBytes = new byte[cipherTextBlockSize / 2];
            Array.Copy(block, 0, aBytes, 0, aBytes.Length);
            byte[] bBytes = new byte[cipherTextBlockSize / 2];
            Array.Copy(block, aBytes.Length, bBytes, 0, bBytes.Length);
            BigInteger A = new BigInteger(aBytes);
            BigInteger B = new BigInteger(bBytes);
            BigInteger M = (B *
                A.modPow(keyStruct.X, keyStruct.P).modInverse(keyStruct.P))
                % keyStruct.P;
            byte[] mBytes = M.getBytes();
            if (mBytes.Length < plaintextBlockSize)
            {
                byte[] fullResult = new byte[plaintextBlockSize];
                Array.Copy(mBytes, 0, fullResult,
                    plaintextBlockSize - mBytes.Length, mBytes.Length);
                mBytes = fullResult;
            }
            return mBytes;
        }
        protected override byte[] ProcessFinalDataBlock(byte[] finalBlock)
        {
            if (finalBlock.Length > 0)
            {
                return ProcessDataBlock(finalBlock);
            }
            else
            {
                return new byte[0];
            }
        }
    }
}
