using SecurityLibrary.AES;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        // function to calc power and mod num
        public static int Mod_Power(int num, int pow, int mod)
        {
            int result = 1;
            for (int i = 0; i < pow; i++)
            {
                result = (result * num) % mod;
            }
            return result;
        }
        public int Encrypt(int p, int q, int M, int e)
        {
            // Cipher Text(c) = M^e mod (p*q)
            int n = p * q;
            int C = Mod_Power(M, e, n);
            return C;
        }
        public int Decrypt(int p, int q, int C, int e)
        {
            // Plain Text (M) = C^d mod (p*q)
            // d = e^-1 mod (p-1*q-1)
            int n = p * q;
            int totient = (p - 1) * (q - 1);
            int d = new ExtendedEuclid().GetMultiplicativeInverse(e, (int)totient);
            int M = Mod_Power(C, d, n);
            return M;
        }
    }
}
