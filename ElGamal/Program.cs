using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;
using static ElGamal.Program;

namespace ElGamal
{
    public class Program
    {
        // It was possible to generate only a large prime number, and the primitive root was not found =(
        static BigInteger p = BigInteger.Parse("88223122544646658283681434640208893220362582172103052885719698861762572726697450502432036576104091490628711789663670265636287133169953380945135615346355392285702605798118791415610040115678873775823942828511390133447314716493589685281441054923778513459562941041603013629968684091557378283599568623324924976404051924096409566612882818868202897667300401866254627246785073340115895407997817713220794875883328816076815735325375075342778173962121693855551080154766586459679672520353724098929823811600057459974336728522631739340504843280579251883853774957886562358115097900767977250623657679371784368187958802287310332313");
        static BigInteger g = BigInteger.Parse("455827445454523554228");

        public class KeyPair
        {
            public BigInteger Public;
            public BigInteger Private;
        }

        public class Signature
        {
            public BigInteger R;
            public BigInteger S;
        }

        public class Message
        {
            public BigInteger X;
            public BigInteger Y;
        }
        static void Main(string[] args)
        {
            KeyPair pair = GenerateKeyPair();
            string message = "Message for check! ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
            Signature sign = Sign(message, pair);
            Console.WriteLine(CheckSign(message, pair, sign));
            Console.WriteLine(Encode(Code(message, pair), pair));
        }

        static int GenerateRandomInt()
        {
            Random rand = new Random();
            int i;

            i = rand.Next(20, 2048);

            return i;
        }
        static BigInteger GenerateRandomBigInteger(int bitLength)
        {
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                BigInteger primeCandidate;

                byte[] bytes = new byte[bitLength / 8];
                rng.GetBytes(bytes);
                bytes[bytes.Length - 1] &= (byte)(255 >> (8 - bitLength % 8));

                primeCandidate = new BigInteger(bytes);

                return primeCandidate;
            }
        }
        static KeyPair GenerateKeyPair()
        {
            KeyPair pair = new KeyPair();
            do
            {
                pair.Private = GenerateRandomBigInteger(GenerateRandomInt());
            } while (pair.Private > p - 1 || pair.Private < 1);
            pair.Public = BigInteger.ModPow(g, pair.Private, p);

            return pair;
        }

        static Signature Sign(string message, KeyPair kp)
        {
            Signature sign = new Signature();
            BigInteger k;
            do
            {
                k = GenerateRandomBigInteger(GenerateRandomInt());
            } while (k > p - 1 || k < 1);
            sign.R = BigInteger.ModPow(g, k, p);
            byte[] hashBytes;
            using (SHA256 sha256 = SHA256.Create())
            {
                hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(message));
            }
            BigInteger hash = new BigInteger(hashBytes);

            BigInteger x = (hash - kp.Private * sign.R) % (p - 1);
            if (x < 0)
            {
                x += (p - 1);
            }

            BigInteger kInv = modInverse(k, p - 1);
            sign.S = (x * kInv) % (p - 1);

            return sign;
        }

        static BigInteger modInverse(BigInteger a, BigInteger m)
        {
            BigInteger m0 = m, t, q;
            BigInteger x0 = 0, x1 = 1;

            if (m <= 1)
            {
                return 0;
            }

            while (a > 1)
            {
                if (m == 0)
                {
                    break; 
                }
                q = a / m;
                t = m;
                m = a % m; 
                a = t;
                t = x0;
                x0 = x1 - q * x0;
                x1 = t;
            }

            if (x1 < 0)
            {
                x1 += m0;
            }

            return x1;
        }

        static bool CheckSign(string message, KeyPair kp, Signature sign)
        {
            BigInteger y = modInverse(kp.Public, p - 1);
            byte[] hashBytes;
            using (SHA256 sha256 = SHA256.Create())
            {
                hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(message));
            }
            BigInteger hash = new BigInteger(hashBytes);
            BigInteger sInv = modInverse(sign.S, p - 1);
            BigInteger u1 = (hash * sInv) % (p - 1);
            if (u1 < 0)
            {
                u1 += (p - 1);
            }
            BigInteger u2 = (sign.R * sInv) % (p - 1);
            if (u2 < 0)
            {
                u2 += (p - 1);
            }
            BigInteger v = (BigInteger.ModPow(g, u1, p) * BigInteger.ModPow(kp.Public, u2, p)) % p;
            return v == sign.R;
        }

        static List<Message> Code(string message, KeyPair pair)
        {
            List<Message> messages = new List<Message>();
            int blockSize = 100;
            for (int i = 0; i < message.Length; i += blockSize)
            {
                string block = message.Substring(i, Math.Min(blockSize, message.Length - i));
                Message m = new Message();
                BigInteger k = GenerateRandomBigInteger(GenerateRandomInt());
                m.X = BigInteger.ModPow(g, k, p);
                byte[] bytes = Encoding.UTF8.GetBytes(block);
                m.Y = (BigInteger.ModPow(pair.Public, k, p) * new BigInteger(bytes)) % p;
                messages.Add(m);
            }
            return messages;
        }

        static string Encode(List<Message> messages, KeyPair pair)
        {
            StringBuilder decodedString = new StringBuilder();
            foreach (var message in messages)
            {
                BigInteger s = BigInteger.ModPow(message.X, pair.Private, p);
                BigInteger invS = modInverse(s, p);
                BigInteger m = (message.Y * invS) % p;
                byte[] messageBytes = m.ToByteArray();
                decodedString.Append(Encoding.UTF8.GetString(messageBytes));
            }
            return decodedString.ToString();
        }

        // I used this for generate p and g
        //static BigInteger GenerateRandomPrime(int bitLength)
        //{
        //    using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
        //    {
        //        BigInteger primeCandidate;
        //        do
        //        {
        //            byte[] bytes = new byte[bitLength / 8];
        //            rng.GetBytes(bytes);
        //            bytes[bytes.Length - 1] &= (byte)(255 >> (8 - bitLength % 8));

        //            primeCandidate = new BigInteger(bytes);
        //        }
        //        while (!IsProbablePrime(primeCandidate, 10));

        //        return primeCandidate;
        //    }
        //}
        //static bool IsProbablePrime(BigInteger n, int k)
        //{
        //    if (n <= 1)
        //    {
        //        return false;
        //    }
        //    if (n == 2 || n == 3)
        //    {
        //        return true;
        //    }
        //    if (n % 2 == 0)
        //    {
        //        return false;
        //    }

        //    BigInteger d = n - 1;
        //    int s = 0;

        //    while (d % 2 == 0)
        //    {
        //        d /= 2;
        //        s++;
        //    }

        //    Random rand = new Random();
        //    for (int i = 0; i < k; i++)
        //    {
        //        BigInteger a = RandomInRange(2, n - 2, rand);
        //        BigInteger x = BigInteger.ModPow(a, d, n);

        //        if (x == 1 || x == n - 1)
        //        {
        //            continue;
        //        }

        //        for (int j = 0; j < s - 1; j++)
        //        {
        //            x = BigInteger.ModPow(x, 2, n);
        //            if (x == n - 1)
        //            {
        //                break;
        //            }
        //        }

        //        if (x != n - 1)
        //        {
        //            return false;
        //        }
        //    }

        //    return true;
        //}
        //public static BigInteger FindPrimitiveRoot(BigInteger m)
        //{
        //    if (m <= 1)
        //    {
        //        throw new ArgumentException("Modulus must be greater than 1.");
        //    }

        //    if (!IsPrime(m))
        //    {
        //        throw new ArgumentException("Modulus must be a prime number.");
        //    }

        //    BigInteger phi = m - 1;

        //    BigInteger g1 = BigInteger.Parse("10000000000000000000000000000000000000000000");

        //    for (BigInteger g = 2; g < m; g++)
        //    {
        //        if (IsCoprime(g, m) && IsSquareRoot(g, phi, m))
        //        {
        //            return g;
        //        }

        //        if(g % g1 == 0)
        //        {
        //            Console.WriteLine(g);
        //            Console.WriteLine("========================================");
        //        }
        //    }

        //    throw new Exception("Primitive root not found.");
        //}

        //private static bool IsPrime(BigInteger n)
        //{
        //    if (n <= 1)
        //    {
        //        return false;
        //    }

        //    for (BigInteger i = 2; i * i <= n; i++)
        //    {
        //        if (n % i == 0)
        //        {
        //            return false;
        //        }
        //    }

        //    return true;
        //}

        //private static bool IsCoprime(BigInteger a, BigInteger b)
        //{
        //    return BigInteger.GreatestCommonDivisor(a, b) == 1;
        //}

        //private static bool IsSquareRoot(BigInteger g, BigInteger phi, BigInteger m)
        //{
        //    BigInteger phiDiv2 = phi / 2;
        //    return BigInteger.ModPow(g, phiDiv2, m) != 1;
        //}
    }
}