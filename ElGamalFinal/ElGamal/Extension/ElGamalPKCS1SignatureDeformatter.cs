using ElGamal.Models;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace ElGamal.Extension
{
    public class ElGamalPKCS1SignatureDeformatter : AsymmetricSignatureDeformatter
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

        public override bool VerifySignature(byte[] data, byte[] signature)
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
                   = ElGamalSignatureFormatHelper.CreateEMSA_PKCS1_v1_5_ENCODE(
                       data, hashAlg, key.KeyStruct.P.bitCount());

                return key.VerifySignature(pkcs, signature);
            }
        }
    }
 }
