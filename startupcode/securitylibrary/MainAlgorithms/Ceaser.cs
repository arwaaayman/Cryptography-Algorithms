using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        char[] alphabet = new char[26] { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
        String output = "";
        public string Encrypt(string plainText, int key)
        {
            char[] text = plainText.ToUpper().ToCharArray();

            for (int i = 0; i < text.Length; i++)
            {
                for (int j = 0; j < alphabet.Length; j++)
                {
                    if (text[i] == alphabet[j])
                    {
                        output += alphabet[(j + key) % 26].ToString();
                        break;
                    }
                }
            }
            return output;
        }

        public string Decrypt(string cipherText, int key)
        {
            int index;
            char[] text = cipherText.ToUpper().ToCharArray();

            for (int i = 0; i < text.Length; i++)
            {
                for (int j = 0; j < alphabet.Length; j++)
                {
                    if (text[i] == alphabet[j])
                    {
                        index = (j - key) % 26;
                        if (index < 0)
                        {
                            index += 26;
                            output += alphabet[index].ToString();
                            break;
                        }
                        else
                        {
                            output += alphabet[index].ToString();
                            break;
                        }
                    }
                }
            }
            return output;
        }

        public int Analyse(string plainText, string cipherText)
        {
            int PTindex = 0;
            int CTindex = 0;
            for (int j = 0; j < alphabet.Length; j++)
            {
                if (char.ToUpper(plainText[0]) == alphabet[j])
                {
                    PTindex = j;
                    break;
                }
            }
            for (int j = 0; j < alphabet.Length; j++)
            {
                if (char.ToUpper(cipherText[0]) == alphabet[j])
                {
                    CTindex = j;
                    break;
                }
            }

            if ((CTindex - PTindex) < 0)
            {
                return (CTindex - PTindex) + 26;
            }
            else
            {
                return (CTindex - PTindex) % 26;
            }
        }
    }
}