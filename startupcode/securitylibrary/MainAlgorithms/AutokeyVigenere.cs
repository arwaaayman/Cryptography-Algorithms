using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        char[] alphabet = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };


        public string Analyse(string plainText, string cipherText)
        {
            string key_stream = "";
            string key = "";
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();


            for (int i = 0; i < cipherText.Length; i++)
            {
                key_stream = key_stream + alphabet[(Array.IndexOf(alphabet, cipherText[i]) - Array.IndexOf(alphabet, plainText[i]) + 26) % 26];
            }

            for (int i = 0; i < key_stream.Length; i++)
            {
                if (cipherText.Equals(Encrypt(plainText, key)))
                {

                    break;
                }
                else
                {
                    key += key_stream[i];

                }

            }

            return key;

        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            char[] decryptedMessage = new char[cipherText.Length];

            int count = 0;

            for (int i = 0; i < cipherText.Length; i++)
            {
                Console.WriteLine("key :" + key[i]);


                decryptedMessage[i] = alphabet[(Array.IndexOf(alphabet, cipherText[i]) - Array.IndexOf(alphabet, key[i]) + 26) % 26];
                if (key.Length < cipherText.Length)
                {
                    key += decryptedMessage[count];
                    count++;
                }


            }

            return new string(decryptedMessage);
        }

        public string Encrypt(string plainText, string key)
        {
            char[] ciphertxt = new char[plainText.Length];
            char[] keystream = new char[plainText.Length];
            for (int i = 0; i < key.Length; i++)
            {
                keystream[i] = key[i];

            }
            for (int i = 0; i < plainText.Length - key.Length; i++)
            {
                keystream[i + key.Length] = plainText[i];

            }

           
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] != ' ')
                {
                    ciphertxt[i] = alphabet[(Array.IndexOf(alphabet, plainText[i]) + Array.IndexOf(alphabet, keystream[i])) % 26];
                }
                else
                {
                    ciphertxt[i] = plainText[i];
                }
            }

            return new string(ciphertxt);

        }
    }
}
