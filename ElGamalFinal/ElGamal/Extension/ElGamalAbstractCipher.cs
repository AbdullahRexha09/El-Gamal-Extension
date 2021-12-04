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
        public byte[] ProcessData(byte[] data)
        {

            MemoryStream stream = new MemoryStream();
            int completeBlocks = data.Length / blockSize;

            byte[] block = new byte[blockSize];

            int i = 0;
            for (; i < completeBlocks; i++)
            {
                Array.Copy(data, i * blockSize, block, 0, blockSize);
                byte[] x_result = ProcessDataBlock(block);
                stream.Write(x_result, 0, x_result.Length);
            }

            byte[] finalBlock = new byte[data.Length -
                (completeBlocks * blockSize)];
            Array.Copy(data, i * blockSize, finalBlock, 0,
                finalBlock.Length);

            byte[] finalResult = ProcessFinalDataBlock(finalBlock);

            stream.Write(finalResult, 0, finalResult.Length);

            return stream.ToArray();
        }
        protected abstract byte[] ProcessDataBlock(byte[] p_block);
        protected abstract byte[] ProcessFinalDataBlock(byte[] p_final_block);



    }
}
