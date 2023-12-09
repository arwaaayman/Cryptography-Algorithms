using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {

        readonly char[] alphabet = new char[] {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z'};

        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            //Create Array for key and full if with space
            char[] key = new char[26];
            for (int i = 0; i < 26; i++)
                key[i] = ' ';

            //Map plainText with cipherText to get some characters of key
            for (int i = 0; i < plainText.Length; i++)
            {
                int index = Array.IndexOf(alphabet, plainText[i]);
                key[index] = cipherText[i];
            }

            //Get index of first character founded in key to use it in serch of rest of key
            int start_index = -1;
            for (int i = 0; i < key.Length; i++) 
            {
                if (key[i] != ' ') {
                    start_index = Array.IndexOf(alphabet, key[i]);
                    break;
                }
            }

            //Get the rest of key from alphbet and store it in remender variable (before start_index and then after it)
            StringBuilder rem = new StringBuilder("");
            for (int i = start_index+1; i < 26; i++)
            {
                if (!key.Contains(alphabet[i]))
                    rem.Append(alphabet[i]);
            }
            for (int i = 0; i < start_index; i++)
            {
                if (!key.Contains(alphabet[i]))
                    rem.Append(alphabet[i]);
            }

            //Complete key with remender characters
            int c = 0;
            for (int j = 0; j < 26; j++)
            {
                if (key[j] == ' ')
                {
                    key[j] = rem[c];
                    c++;
                }       
            }

            //Cast key to string and return it
            string k = new string(key);
            return k ;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            char[] keyArr = key.ToCharArray();
            char[] cipherLetters = cipherText.ToLower().ToCharArray();

            StringBuilder plainText = new StringBuilder();

            for (int i = 0; i < cipherLetters.Length; i++)
            {
                int index = Array.IndexOf(keyArr, cipherLetters[i]);
                plainText.Append(alphabet[index]);
            }
            return plainText.ToString();
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
             char[] keyArr = key.ToCharArray();
             char[] plainLetters = plainText.ToLower().ToCharArray();

            StringBuilder cipherText = new StringBuilder();

            for (int i = 0; i < plainLetters.Length; i++)
             {
                 int index = Array.IndexOf(alphabet, plainLetters[i]);
                 cipherText.Append(keyArr[index]);
             }
             return cipherText.ToString();
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            //throw new NotImplementedException();
            cipher = cipher.ToLower();
            //Create array of char and store alphabet ordered based on given Frequency Information above
            char [] alphabetFreq = {'e','t','a','o','i','n','s','r','h','l','d','c','u','m','f','p','g','w','y','b','v','k','x','j','g','z'}; 
            
            //Creare dectionary to store each character of cipherText with it's frequency
            Dictionary<char, int> cipherFreq = new Dictionary<char, int>();

            //Calculate frquency for each character in cipher text
            for (int i = 0; i < cipher.Length; i++)
            {
                if (cipherFreq.ContainsKey(cipher[i]))
                    cipherFreq[cipher[i]]++;
                else
                    cipherFreq.Add(cipher[i], 0);   
            }

            //Order dictionary of character of cipher text decending based on value (frecuncy).
            var dict = from entry in cipherFreq orderby entry.Value descending select entry;

            //Map each character in dict to alphabetFreq.
            Dictionary<char, char> keyDic = new Dictionary<char, char>();
            int c = 0;
            foreach (var item in dict)
            {
                keyDic.Add(item.Key, alphabetFreq[c]);
                c++;
            }

            StringBuilder result = new StringBuilder("");
            for (int i = 0; i < cipher.Length; i++)
            {
                result.Append(keyDic[cipher[i]]);
            }

            return result.ToString();
        }
    }
}
