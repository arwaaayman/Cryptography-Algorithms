using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            //throw new NotImplementedException();
            int[,] matrix = new int[100, 7];
            matrix[0, 0] = 0;
            matrix[0, 1] = 1;
            matrix[0, 2] = 0;
            matrix[0, 3] = baseN;
            matrix[0, 4] = 0;
            matrix[0, 5] = 1;
            matrix[0, 6] = number;

            int i;
            for (i = 1 ; i < 100; i++)
            {
                matrix[i, 0] = matrix[i - 1, 3] / matrix[i - 1, 6];//Q

                matrix[i, 1] = matrix[i - 1, 4];//A1
                matrix[i, 2] = matrix[i - 1, 5];//A2
                matrix[i, 3] = matrix[i - 1, 6];//A3

                matrix[i, 4] = matrix[i - 1, 1] - (matrix[i, 0] * matrix[i - 1, 4]);//B1
                matrix[i, 5] = matrix[i - 1, 2] - (matrix[i, 0] * matrix[i - 1, 5]);//B2
                matrix[i, 6] = matrix[i - 1, 3] - (matrix[i, 0] * matrix[i - 1, 6]);//B3

                if (matrix[i, 6] == 0 || matrix[i, 6] == 1)
                    break;
            }

            if (matrix[i, 6] == 1)
                return matrix[i, 5] < 0 ? (matrix[i, 5] + baseN) : matrix[i, 5];
            
            return -1;
        }
    }
}
