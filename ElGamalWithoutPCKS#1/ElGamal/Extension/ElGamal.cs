using ElGamal.Structs;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace ElGamal.Models
{
    public abstract class ElGamal : AsymmetricAlgorithm
    {
        public abstract void ImportParameters(ElGamalParameters p_parameters);
        public abstract ElGamalParameters ExportParameters(bool p_include_private_params);
        public abstract byte[] Sign(byte[] p_hashcode);
        public abstract bool VerifySignature(byte[] p_hashcode, byte[] p_signature);
        public override string ToXmlString(bool includePrivate)
        {
            ElGamalParameters dtparams = ExportParameters(includePrivate);
            StringBuilder x_sb = new StringBuilder();
            x_sb.Append("<ElGamalKeyValue>");
            x_sb.Append("<P>" + Convert.ToBase64String(dtparams.P) + "</P>");
            x_sb.Append("<G>" + Convert.ToBase64String(dtparams.G) + "</G>");
            x_sb.Append("<Y>" + Convert.ToBase64String(dtparams.Y) + "</Y>");
            if (includePrivate)
            {
                x_sb.Append("<X>" + Convert.ToBase64String(dtparams.X) + "</X>");
            }
            x_sb.Append("</ElGamalKeyValue>");
            return x_sb.ToString();
        }
        public override void FromXmlString(string pString)
        {
            ElGamalParameters xParams = new ElGamalParameters();
            XmlTextReader reader =
                new XmlTextReader(new System.IO.StringReader(pString));

            while (reader.Read())
            {
                if (true || reader.IsStartElement())
                {
                    switch (reader.Name)
                    {
                        case "P":
                            xParams.P =
                                Convert.FromBase64String(reader.ReadString());
                            break;
                        case "G":
                            xParams.G =
                                Convert.FromBase64String(reader.ReadString());
                            break;
                        case "Y":
                            xParams.Y =
                                Convert.FromBase64String(reader.ReadString());
                            break;
                        case "X":
                            xParams.X =
                                Convert.FromBase64String(reader.ReadString());
                            break;
                    }
                }
            }
            // Import the result
            ImportParameters(xParams);
        }
    }
}

