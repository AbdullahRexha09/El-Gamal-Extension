using ElGamal.Models;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace ElGamal.Extension
{
    public class ElGamalPKCS1SignatureFormatter : AsymmetricSignatureFormatter
    {
        private string hashName;
        private ElGamalManaged key;
        public override void SetHashAlgorithm(string pName)
        {
            hashName = pName;
        }
        public override void SetKey(AsymmetricAlgorithm pKey)
        {
            if (pKey is ElGamalManaged)
            {
                key = pKey as ElGamalManaged;
            }
            else
            {
                throw new ArgumentException(
                    "Key is not an instance of ElGamalManaged", "p_key");
            }
        }
        public override byte[] CreateSignature(byte[] data)
        {
            if (hashName == null || key == null)
            {
                throw new
                    CryptographicException("Key and Hash Algorithm must be set");
            }
            else
            {
                HashAlgorithm hashAlg = HashAlgorithm.Create(hashName);
                byte[] pkcs
                   = ElGamalSignatureFormatHelper.CreateEMSA_PKCS1_v1_5_ENCODE(data,
                   hashAlg, key.KeyStruct.P.bitCount());
                return key.Sign(pkcs);
            }
        }
        }
}
