using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    /// 
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        DES dES = new DES();

        public string Decrypt(string cipherText, List<string> key)
        {
            string plaintext = dES.Decrypt(cipherText, key[1]);
            plaintext = dES.Encrypt(plaintext, key[0]);
            plaintext = dES.Decrypt(plaintext, key[1]);

            return plaintext;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            string ciphertext = dES.Encrypt(plainText, key[0]);
            ciphertext = dES.Decrypt(ciphertext, key[1]);
            ciphertext = dES.Encrypt(ciphertext, key[0]);

            return ciphertext;
        }
        
        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
