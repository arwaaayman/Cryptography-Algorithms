using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        readonly char[] alphabet = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };

        private string generateKey(string text, string key) {

            text = text.ToLower();
            StringBuilder keyStream = new StringBuilder(key);

            for (int i = 0; i < (text.Length - key.Length); i++)
            {
                keyStream.Append(key[i % key.Length]);
            }

            return keyStream.ToString();
        }

        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            StringBuilder key = new StringBuilder();
            for (int i = 0; i < plainText.Length; i++)
            {
                int cipherTextIndex = Array.IndexOf(alphabet, cipherText[i]);
                int plainTextIndex = Array.IndexOf(alphabet, plainText[i]);
                int index = (cipherTextIndex - plainTextIndex) + 26;
                key.Append(alphabet[index % 26]);
            }

            String newKey = key[0].ToString();
            int counter = 1;
            while (Encrypt(plainText, newKey.ToString()).ToString() != cipherText)
            {
                newKey += key[counter];
                counter++;
            }

            return newKey.ToString();
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            string keyStream = generateKey(cipherText, key);
            StringBuilder plainText = new StringBuilder();

            //Di = (Ei - Ki + 26) mod 26
            for (int i = 0; i < cipherText.Length; i++)
            {
                int cipherTextIndex = Array.IndexOf(alphabet, cipherText[i]);
                int keyIndex = Array.IndexOf(alphabet, keyStream[i]);
                int index = (cipherTextIndex - keyIndex)+26;
                plainText.Append(alphabet[index%26]);
            }

            return plainText.ToString();
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToLower();
            string keyStream = generateKey(plainText, key); ;
            StringBuilder cipherText = new StringBuilder();

            //Ei = (Pi + Ki) mod 26
            for (int i = 0; i < plainText.Length; i++)
            {
                int plainTextIndex = Array.IndexOf(alphabet, plainText[i]);
                int keyIndex = Array.IndexOf(alphabet, keyStream[i]);
                int index = (plainTextIndex + keyIndex) % 26;
                cipherText.Append(alphabet[index]);
            }

            return cipherText.ToString();
        }
    }
}