using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToUpper();
            plainText = plainText.ToUpper();
            int[] possibleKeys = new int[plainText.Length];
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] == cipherText[1]) possibleKeys[i] = i;
            }
            for (int i = 0; i < possibleKeys.Length; i++)
            {
                string s = Encrypt(plainText, possibleKeys[i]).ToUpper();
                if (String.Equals(cipherText, s))
                {
                    return possibleKeys[i];
                }
            }
            return -1;
        }

        public string Decrypt(string cipherText, int key)
        {
            int PTLength = (int)Math.Ceiling((double)cipherText.Length / key);
            return Encrypt(cipherText, PTLength).ToUpper();
        }

        public string Encrypt(string plainText, int key)
        {
            String output = "";
            char[] text = plainText.ToUpper().ToCharArray();

            for (int i = 0; i < key; i++)
            {
                for (int j = i; j < text.Length; j += key)
                {
                    output += text[j];
                }
            }
            return output;

        }
    }
}