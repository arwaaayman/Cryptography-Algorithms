using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            int row = 0;
            int col = 0;
            int counter = 0;
            cipherText = cipherText.ToLower();
            

            for (int i = 2; i < 8; i++)
            {
                if (plainText.Length % i == 0)
                {
                    col = i;
                }
            }

            row = plainText.Length / col;
            char[,] plainMatrix = new char[row, col];
            char[,] cipherMatrix = new char[row, col];
            List<int> key = new List<int>(col);

            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    if (counter < plainText.Length) {
                        plainMatrix[i, j] = plainText[counter];
                        counter++;
                    }
                        
                }
            }

            counter = 0;
            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < row; j++)
                {
                    if (counter < plainText.Length)
                    {
                        cipherMatrix[j, i] = cipherText[counter];
                        counter++;
                    }
                }
            }

            int check = 0;
            for (int i = 0; i < col; i++)
            {
                for (int k = 0; k < col; k++)
                {
                    for (int j = 0; j < row; j++)
                    {
                        if (plainMatrix[j, i] == cipherMatrix[j, k])
                        {
                            check++;
                        }
                        if (check == row)
                            key.Add(k + 1); //+1 key base 1, index in cipher and plain base 0.
                    }
                    check = 0;
                }
            }

            if (key.Count == 0)
            {
                for (int i = 0; i < col + 2; i++)
                {
                    key.Add(0);
                }
            }
            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int row;
            int col = key.Count;
            if (cipherText.Length % key.Count == 0)
            {
                row = cipherText.Length / key.Count;
            }else
            {
                row = (int)Math.Ceiling((double)cipherText.Length / col);
            }

            Char[,] matrix = new char[row, col];
            int colFree = (row * col) - cipherText.Length;

            int counter = 0;
            int count = 1;
            //the matrix
            for (int i = 0; i < col; i++)
            {
                int index = key.IndexOf(count);
                count++;
                for (int j = 0; j < row; j++)
                {
                    if (j != row - 1)
                    {
                        matrix[j, index] = cipherText[counter];
                        counter++;
                    }
                    else if ((j == row - 1) && !(((i + 1) + colFree) > col))
                    {
                        matrix[j, index] = cipherText[counter];
                        counter++;
                    }
                }
            }
            String plain_text = "";
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    if (matrix[i, j] != '\0')
                    {
                        plain_text += matrix[i, j];
                    }
                }
            }
            return plain_text;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int row;
            int col = key.Count;

            if (plainText.Length % key.Count == 0)
            {
                row = plainText.Length / key.Count;
            }else
            {
                row = (int)Math.Ceiling((double)plainText.Length / col);
            }
            Char[,] matrix = new char[row, col];
            int counter = 0;
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col && counter < plainText.Length; j++)
                {
                    matrix[i, j] = plainText[counter];
                    counter++;
                }
            }
            String cipher_text = "";
            for (int i = 1; i <= col; i++)
            {
                int index = key.IndexOf(i);
                for (int j = 0; j < row; j++)
                {
                    if (matrix[j, index] != '\0')
                    {
                        cipher_text += matrix[j, index];
                    }
                }
            }
            return cipher_text;
        }
    }
}
