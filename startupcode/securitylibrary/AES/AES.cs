using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        #region S-Box and Inverse S-Box
        //Encryption
        readonly string[,] sbox = new string[,] {
            {"63","7c","77","7b","f2","6b","6f","c5","30","01","67","2b","fe","d7","ab","76"},
            {"ca","82","c9","7d","fa","59","47","f0","ad","d4","a2","af","9c","a4","72","c0"},
            {"b7","fd","93","26","36","3f","f7","cc","34","a5","e5","f1","71","d8","31","15"},
            {"04","c7","23","c3","18","96","05","9a","07","12","80","e2","eb","27","b2","75"},
            {"09","83","2c","1a","1b","6e","5a","a0","52","3b","d6","b3","29","e3","2f","84"},
            {"53","d1","00","ed","20","fc","b1","5b","6a","cb","be","39","4a","4c","58","cf"},
            {"d0","ef","aa","fb","43","4d","33","85","45","f9","02","7f","50","3c","9f","a8"},
            {"51","a3","40","8f","92","9d","38","f5","bc","b6","da","21","10","ff","f3","d2"},
            {"cd","0c","13","ec","5f","97","44","17","c4","a7","7e","3d","64","5d","19","73"},
            {"60","81","4f","dc","22","2a","90","88","46","ee","b8","14","de","5e","0b","db"},
            {"e0","32","3a","0a","49","06","24","5c","c2","d3","ac","62","91","95","e4","79"},
            {"e7","c8","37","6d","8d","d5","4e","a9","6c","56","f4","ea","65","7a","ae","08"},
            {"ba","78","25","2e","1c","a6","b4","c6","e8","dd","74","1f","4b","bd","8b","8a"},
            {"70","3e","b5","66","48","03","f6","0e","61","35","57","b9","86","c1","1d","9e"},
            {"e1","f8","98","11","69","d9","8e","94","9b","1e","87","e9","ce","55","28","df"},
            {"8c","a1","89","0d","bf","e6","42","68","41","99","2d","0f","b0","54","bb","16"}};
        
        //Decryption
        readonly string[,] inverse_sbox = new string[,] {
            {"52","09","6a","d5","30","36","a5","38","bf","40","a3","9e","81","f3","d7","fb"},
            {"7c","e3","39","82","9b","2f","ff","87","34","8e","43","44","c4","de","e9","cb"},
            {"54","7b","94","32","a6","c2","23","3d","ee","4c","95","0b","42","fa","c3","4e"},
            {"08","2e","a1","66","28","d9","24","b2","76","5b","a2","49","6d","8b","d1","25"},
            {"72","f8","f6","64","86","68","98","16","d4","a4","5c","cc","5d","65","b6","92"},
            {"6c","70","48","50","fd","ed","b9","da","5e","15","46","57","a7","8d","9d","84"},
            {"90","d8","ab","00","8c","bc","d3","0a","f7","e4","58","05","b8","b3","45","06"},
            {"d0","2c","1e","8f","ca","3f","0f","02","c1","af","bd","03","01","13","8a","6b"},
            {"3a","91","11","41","4f","67","dc","ea","97","f2","cf","ce","f0","b4","e6","73"},
            {"96","ac","74","22","e7","ad","35","85","e2","f9","37","e8","1c","75","df","6e"},
            {"47","f1","1a","71","1d","29","c5","89","6f","b7","62","0e","aa","18","be","1b"},
            {"fc","56","3e","4b","c6","d2","79","20","9a","db","c0","fe","78","cd","5a","f4"},
            {"1f","dd","a8","33","88","07","c7","31","b1","12","10","59","27","80","ec","5f"},
            {"60","51","7f","a9","19","b5","4a","0d","2d","e5","7a","9f","93","c9","9c","ef"},
            {"a0","e0","3b","4d","ae","2a","f5","b0","c8","eb","bb","3c","83","53","99","61"},
            {"17","2b","04","7e","ba","77","d6","26","e1","69","14","63","55","21","0c","7d"}};
        #endregion

        #region MixColumns Inverse MixColumns
        //Encryption
        readonly string[,] MixColumnFactor = new string[,]{
            {"02","03", "01", "01"},
            {"01","02", "03", "01"},
            {"01","01", "02", "03"},
            {"03","01", "01", "02"}
            };

        //Decryption
        readonly string[,] Inverse_MixColumnFactor = new string[,]{
            {"0E","0B", "0D", "09"},
            {"09","0E", "0B", "0D"},
            {"0D","09", "0E", "0B"},
            {"0B","0D", "09", "0E"}
            };
        #endregion

        #region Rcon
        public string[,] Rcon = new string[,]{
        {"01","02","04","08","10","20","40","80","1b","36"},
        {"00","00","00","00","00","00","00","00","00","00"},
        {"00","00","00","00","00","00","00","00","00","00"},
        {"00","00","00","00","00","00","00","00","00","00"}};
        #endregion

        #region Functions
        private string[,] TextToMatrix(string text) {
            //text = text.Substring(2); //remoxing 0x
            string[,] matrix = new string[4, 4];
            char[] textToCharArr = text.ToCharArray();
            int count = 2;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    matrix[j, i] = textToCharArr[count] + "" +textToCharArr[count + 1];
                    count += 2;
                }
            }
            return matrix;
        }
        private string[,] ShiftRowsLeft(string[,] matrix)
        {
            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < i; j++)
                {
                    string temp = matrix[i, 0];
                    matrix[i, 0] = matrix[i, 1];
                    matrix[i, 1] = matrix[i, 2];
                    matrix[i, 2] = matrix[i, 3];
                    matrix[i, 3] = temp;
                }
            }
            return matrix;
        }
        private string[,] ShiftRowsRight(string[,] matrix)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < i; j++)
                {
                    string temp = matrix[i, 3];
                    matrix[i, 3] = matrix[i, 2];
                    matrix[i, 2] = matrix[i, 1];
                    matrix[i, 1] = matrix[i, 0];
                    matrix[i, 0] = temp;
                }
            }
            return matrix;
        }
        private string[,] SubBytes(string[,] matrix, string[,] box)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string temp = matrix[i, j];
                    int row = Convert.ToInt32(temp[0].ToString(), 16);
                    int col = Convert.ToInt32(temp[1].ToString(), 16);
                    matrix[i, j] = box[row, col];
                }
            }
            return matrix;
        }
        private string[] SubBytes(string[] array, string[,] box)
        {
            for (int i = 0; i < 4; i++)
            {
                string temp = array[i];
                int row = (int)Convert.ToInt32(temp[0].ToString(), 16);
                int col = (int)Convert.ToInt32(temp[1].ToString(), 16);
                array[i] = box[row, col];
            }
            return array;
        }
        private string[,] XOR(string[,] a, string[,] b)
        {
            string[,] result = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result[i, j] = XOR(a[i, j], b[i, j]);
                }
            }
            return result;
        }
        private string XOR(string a, string b)
        {
            int aDecimal = Convert.ToInt32(a, 16);
            int bDecimal = Convert.ToInt32(b, 16);
            int result = aDecimal ^ bDecimal;

            string resultHex = Convert.ToString(result, 16);

            return resultHex.Length == 1 ? "0" + resultHex : resultHex;

        }
        private string[] RowWord(string[] column)
        {
            string temp = column[0];
            column[0] = column[1];
            column[1] = column[2];
            column[2] = column[3];
            column[3] = temp;
            return column;
        }
        private string[,] KeySchedule(string[,] key)
        {
            string[,] keySchedule = new string[4, 44];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    keySchedule[j, i] = key[j, i];
                }
            }
            
            for (int i = 4; i < 44; i++)
            {
                string[] column1 = new string[4];
                string[] column2 = new string[4];
                
                for (int k = 0; k < 4; k++)
                {
                    column1[k] = keySchedule[k, i - 1];
                    column2[k] = keySchedule[k, i - 4];
                }
                if (i % 4 == 0)
                {
                    column1 = RowWord(column1);
                    column1 = SubBytes(column1, sbox);
                    
                    string[] RconColumn = new string[4];
                    for (int j = 0; j < 4; j++)
                    {
                        RconColumn[j] = Rcon[j, (i / 4) - 1];
                    }

                    for (int j = 0; j < 4; j++)
                    {
                        column1[j] = XOR(column1[j], column2[j]);
                        keySchedule[j, i] = XOR(column1[j], RconColumn[j]);
                    }

                }
                else
                {
                    for (int j = 0; j < 4; j++)
                    {
                        keySchedule[j, i] = XOR(column1[j], column2[j]);
                    }
                }
            }
            return keySchedule;
        }
        private string[,] RoundKey(string[,] keySchedule, int round)
        {
            string[,] roundKey = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    roundKey[j, i] = keySchedule[j, round * 4 + i];
                }
            }
            return roundKey;
        }
        private string[,] AddRoundKry(string[,] mixMatrix, string[,] roundKey)
        {
            return XOR(mixMatrix, roundKey);
        }
        static string BinXOR(string binary1, string binary2)
        {
            string res = "";
            if (binary1 != "" && binary2 != "")
            {
                for (int i = 0; i < 8; i++)
                    res += binary1[i] == binary2[i] ? '0' : '1';
            }
            else if (binary1 == "")
                res = binary2;
            else if (binary2 == "")
                res = binary1;
            return res;
        }
        static string HextoBin(string x)
        {
            x = Convert.ToString(Convert.ToInt32(x.ToString(), 16), 2).PadLeft(8, '0');
            return x;
        }
        static string BintoHex(string x)
        {
            x = Convert.ToString(Convert.ToInt32(x.ToString(), 2), 16);
            return x;
        }
        static string ShiftLeft(StringBuilder binary1)
        {
            for (int i = 0; i < 8; i++)
            {
                if (i == 7)
                {
                    binary1[7] = '0';
                }
                else binary1[i] = binary1[i + 1];
            }
            return binary1.ToString();
        }
        static String Shift_1B(string bin)//shift left and xor with 1B
        {
            if (bin[0] == '0')
            {
                return bin.Remove(0, 1) + "0";
            }
            else
            {
                return BinXOR((bin.Remove(0, 1) + "0"), HextoBin("1B"));
            }
        }
        static string _09(string bin)//bin×09=(((bin×2)×2)×2)+bin
        {
            string res = BinXOR(Shift_1B(Shift_1B(Shift_1B(bin))), bin);
            return res;
        }
        static string _0B(string bin)//bin×0B=((((bin×2)×2)+bin)×2)+bin
        {
            string res = BinXOR(Shift_1B(BinXOR(Shift_1B(Shift_1B(bin)), bin)), bin);
            return res;
        }
        static string _0D(string bin)//bin×0D=((((bin×2)+bin)×2)×2)+bin
        {
            string res = BinXOR(Shift_1B(Shift_1B(BinXOR(Shift_1B(bin), bin))), bin);
            return res;

        }
        static string _0E(string bin)//bin×0E=((((bin×2)+bin)×2)+bin)×2
        {
            string res = Shift_1B(BinXOR(Shift_1B(BinXOR(Shift_1B(bin), bin)), bin));
            return res;

        }
        private string[,] MixColumns(string[,] matrix)
        {
            string[,] mixed = { { "", "", "", "" }, { "", "", "", "" }, { "", "", "", "" }, { "", "", "", "" } };
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        StringBuilder binary1 = new StringBuilder(HextoBin(matrix[k, j]));
                        string res = "";
                        string _1B = HextoBin("1B");

                        if (MixColumnFactor[i, k].Equals("02"))
                        {
                            if (binary1[0] == '1')
                            {
                                ShiftLeft(binary1);
                                res = BinXOR(BinXOR(binary1.ToString(), _1B), res);
                            }
                            else
                                res = ShiftLeft(binary1);
                        }
                        else if (MixColumnFactor[i, k].Equals("01"))
                        {
                            res = binary1.ToString();
                        }
                        else if (MixColumnFactor[i, k].Equals("03"))
                        {
                            res = binary1.ToString();
                            if (binary1[0] == '1')
                            {
                                ShiftLeft(binary1);
                                res = BinXOR(BinXOR(binary1.ToString(), _1B), res);
                            }
                            else
                            {
                                ShiftLeft(binary1);
                                res = BinXOR(binary1.ToString(), res);
                            }
                        }
                        mixed[i, j] = BinXOR(mixed[i, j].PadLeft(8, '0'), res);
                        if (k == 3)
                        {
                            mixed[i, j] = BintoHex(mixed[i, j]).PadLeft(2, '0').ToUpper();
                        }
                    }
                }
            }

            return mixed;
        }
        private string[,] InvMixColumns(string[,] matrix)
        {
            string[,] mixed = { { "", "", "", "" }, { "", "", "", "" }, { "", "", "", "" }, { "", "", "", "" } };
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        StringBuilder binary1 = new StringBuilder(HextoBin(matrix[k, j]));
                        string res = "";
                        if (Inverse_MixColumnFactor[i, k].Equals("09", StringComparison.OrdinalIgnoreCase))
                        {
                            res = _09(binary1.ToString());
                        }
                        else if (Inverse_MixColumnFactor[i, k].Equals("0B", StringComparison.OrdinalIgnoreCase))
                        {
                            res = _0B(binary1.ToString());
                        }
                        else if (Inverse_MixColumnFactor[i, k].Equals("0D", StringComparison.OrdinalIgnoreCase))
                        {
                            res = _0D(binary1.ToString());
                        }
                        else if (Inverse_MixColumnFactor[i, k].Equals("0E", StringComparison.OrdinalIgnoreCase))
                        {
                            res = _0E(binary1.ToString());
                        }
                        mixed[i, j] = BinXOR(mixed[i, j].PadLeft(8, '0'), res);
                        if (k == 3)
                        {
                            mixed[i, j] = BintoHex(mixed[i, j]).PadLeft(2, '0').ToUpper();
                        }
                    }
                }
            }
            return mixed;
        }
        #endregion

        public override string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            string[,] cipherTextMatrix = TextToMatrix(cipherText);
            string[,] keyMatrix = TextToMatrix(key);
            string[,] key_schedule = KeySchedule(keyMatrix);

            cipherTextMatrix = XOR(cipherTextMatrix, RoundKey(key_schedule, 10));
            
            for (int i = 10; i > 0; i--)
            {
                cipherTextMatrix = ShiftRowsRight(cipherTextMatrix);
                cipherTextMatrix = SubBytes(cipherTextMatrix, inverse_sbox);
                cipherTextMatrix = AddRoundKry(cipherTextMatrix, RoundKey(key_schedule, i - 1));
                if (i != 1)
                    cipherTextMatrix = InvMixColumns(cipherTextMatrix);
            }
            string result = "0x";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result += cipherTextMatrix[j, i];
                }
            }

            return result;
        }

        public override string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            string[,] plainTextMatrix = TextToMatrix(plainText);
            string[,] keyMatrix = TextToMatrix(key);
            string[,] key_schedule = KeySchedule(keyMatrix);
            
            plainTextMatrix = XOR(plainTextMatrix, RoundKey(key_schedule, 0));
            
            for (int i = 0; i < 10; i++)
            {
                plainTextMatrix = SubBytes(plainTextMatrix, sbox);
                plainTextMatrix = ShiftRowsLeft(plainTextMatrix);
                if (i != 9)
                    plainTextMatrix = MixColumns(plainTextMatrix);
                plainTextMatrix = AddRoundKry(plainTextMatrix, RoundKey(key_schedule, i + 1));
            }
           
            string result = "0x";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result += plainTextMatrix[j, i];
                }
            }
            
            return result;
        }
    }
}
