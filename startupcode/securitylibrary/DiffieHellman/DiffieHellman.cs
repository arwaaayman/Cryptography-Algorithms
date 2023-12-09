using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public static int Mod_Power(int num, int pow, int mod)
        {
            int result = 1;
            for (int i = 0; i < pow; i++)
            {
                result = (result * num) % mod;
            }
            return result;
        }
        
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            //throw new NotImplementedException();
            List<int> result = new List<int>();
            
            //PUBLIC KEY
            int Ya = Mod_Power(alpha, xa, q);
            int Yb = Mod_Power(alpha, xb, q);
            // PRIVATE KEY
            int K1 = Mod_Power(Ya, xb, q);
            int K2 = Mod_Power(Yb, xa, q);

            result.Add(K1); result.Add(K2);
            return result;
        }
    }
}
