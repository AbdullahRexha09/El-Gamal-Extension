using ElGamal.Structs;
using System;
using System.IO;

namespace ElGamal.Models
{
    public abstract class ElGamalAbstractCipher
    {
        protected int blockSize;
        protected int plaintextBlockSize;
        protected int cipherTextBlockSize;
        protected ElGamalKeyStruct keyStruct;

        public ElGamalAbstractCipher(ElGamalKeyStruct p_key_struct)
        {
            keyStruct = p_key_struct;

            plaintextBlockSize = (p_key_struct.P.bitCount() - 1) / 8;
            cipherTextBlockSize = ((p_key_struct.P.bitCount() + 7) / 8) * 2;

            blockSize = plaintextBlockSize;
        }
        protected abstract byte[] ProcessDataBlock(byte[] p_block);



    }
}
