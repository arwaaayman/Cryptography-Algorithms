using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        /// 
        readonly char[] alphabet = new char[] { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
        private void get_index(char[,] Arr, char str, ref int letter1_row, ref int letter1_col)
        {
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {

                    if (Arr[i, j] == str)
                    {
                        letter1_row = i;
                        letter1_col = j;
                        break;
                    }
                }
            }
        }

        private char[,] generateKey(string key) {
            var uniqueCharArray = key.ToCharArray().Distinct().ToArray();

            var s = new String(uniqueCharArray);
            StringBuilder key1 = new StringBuilder(s);

            for (int count = 0; count < key1.Length; count++)
            {
                if (key1[count] == 'J')
                    key1[count] = 'I';
            }

            char[] key2 = key1.ToString().ToCharArray();
            StringBuilder rem = new StringBuilder();
            for (int count = 0; count < 26; count++)
            {
                if (alphabet[count] != 'J')
                {
                    if (!key2.Contains(alphabet[count]))
                    {
                        rem.Append(alphabet[count]);
                    }
                }
            }

            string k = new string(key2);
            string k2 = rem.ToString();
            string allKey = k + k2;

            char[,] matrix = new char[5, 5];
            int counter = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    matrix[i, j] = allKey[counter];
                    counter++;
                }
            }
            return matrix;
        }

        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();

            StringBuilder tmpstr = new StringBuilder(cipherText);

            for (int i = 0; i < tmpstr.Length; i++)
            {
                if (tmpstr[i] == 'J')
                {
                    tmpstr[i] = 'I';
                }
            }

            for (int i = 0; ((i < tmpstr.Length) && ((i + 1) < tmpstr.Length)); i += 2)
            {
                if (tmpstr[i] == tmpstr[i + 1])
                    tmpstr.Insert(i + 1, 'X');
            }

            if (tmpstr.Length % 2 == 1)
                tmpstr.Append('X');

            char[,] matrix = new char[5, 5];
            matrix = generateKey(key);

            int letter1_row = 0, letter1_col = 0, letter2_row = 0, letter2_col = 0;
            for (int i = 0; i < tmpstr.Length; i += 2)
            {
                get_index(matrix, tmpstr[i], ref letter1_row, ref letter1_col);
                get_index(matrix, tmpstr[i + 1], ref letter2_row, ref letter2_col);

                if (letter1_row == letter2_row)
                {
                    tmpstr[i] = matrix[letter1_row, (letter1_col + 4) % 5];
                    tmpstr[i + 1] = matrix[letter2_row, (letter2_col + 4) % 5];
                }
                else if (letter1_col == letter2_col)
                {
                    tmpstr[i] = matrix[(letter1_row + 4) % 5, letter1_col];
                    tmpstr[i + 1] = matrix[(letter2_row + 4) % 5, letter2_col];
                }
                else
                {
                    tmpstr[i] = matrix[letter1_row, letter2_col];
                    tmpstr[i + 1] = matrix[letter2_row, letter1_col];
                }
            }

            for (int i = tmpstr.Length - 1; i >= 0; i--)
            {
                if (tmpstr[i] == 'X')
                {
                    if (i > 0)
                    {
                        if (i == (tmpstr.Length - 1) && i % 2 != 0)
                        {
                            tmpstr.Remove(i,1);
                        }
                        else if (tmpstr[i-1] == tmpstr[i+1] && i % 2 != 0)
                        {
                            tmpstr.Remove(i, 1);
                        }
                    }
                }
            }
            
            string ciphertext = tmpstr.ToString();
            return ciphertext.ToLower();
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToUpper();
            key = key.ToUpper();

            StringBuilder tmpstr = new StringBuilder(plainText);

            for (int i = 0; i < tmpstr.Length; i++)
            {
                if (tmpstr[i] == 'J')
                {
                    tmpstr[i] = 'I';
                }
            }

            for (int i = 0; ((i < tmpstr.Length) && ((i + 1) < tmpstr.Length)); i += 2)
            {
                if (tmpstr[i] == tmpstr[i + 1])
                    tmpstr.Insert(i + 1, 'X');
            }

            if (tmpstr.Length % 2 == 1)
                tmpstr.Append('X');

            char[,] matrix = new char[5, 5];
            matrix = generateKey(key);

            int letter1_row = 0, letter1_col = 0, letter2_row = 0, letter2_col = 0;
            for (int i = 0; i < tmpstr.Length; i += 2)
            {
                get_index(matrix, tmpstr[i], ref letter1_row, ref letter1_col);
                get_index(matrix, tmpstr[i + 1], ref letter2_row, ref letter2_col);
                if (letter1_row == letter2_row)
                {
                    tmpstr[i] = matrix[letter1_row, (letter1_col + 1) % 5];
                    tmpstr[i + 1] = matrix[letter2_row, (letter2_col + 1) % 5];

                }
                else if (letter1_col == letter2_col)
                {
                    tmpstr[i] = matrix[(letter1_row + 1) % 5, letter1_col];
                    tmpstr[i + 1] = matrix[(letter2_row + 1) % 5, letter2_col];
                }
                else
                {
                    tmpstr[i] = matrix[letter1_row, letter2_col];
                    tmpstr[i + 1] = matrix[letter2_row, letter1_col];
                }
            }

            string ciphertext = tmpstr.ToString();
            return ciphertext.ToUpper();
        }
    }
}