using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace RSADemo
{
    class Program
    {
       
        static void Main(string[] args)
        {
            string javaPrivateKey = @" Java Private here ";
            Console.WriteLine("JAVA Private Key:" + Environment.NewLine + javaPrivateKey + Environment.NewLine);

            string text = " the text what you want to encrypt with RSA privatekey here ";
            Console.WriteLine("content:" + Environment.NewLine + text + Environment.NewLine);

            string dotNetXmlPrivateKey = RSAPrivateKeyJava2DotNet(javaPrivateKey);

            Console.WriteLine("C# Private Key:" + Environment.NewLine + dotNetXmlPrivateKey + Environment.NewLine);

            var result = RSAEncryptByPrivateKey(dotNetXmlPrivateKey, text);
            Console.WriteLine("Result:" + Environment.NewLine + result);

            Console.Read();


        }

        public static string RSAPrivateKeyJava2DotNet(string privateKey)
        {
            RsaPrivateCrtKeyParameters privateKeyParam = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));

            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
                Convert.ToBase64String(privateKeyParam.Modulus.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.PublicExponent.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.P.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.Q.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.DP.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.DQ.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.QInv.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.Exponent.ToByteArrayUnsigned()));
        }





        /// <summary>用私钥给数据进行RSA加密
        /// 
        /// </summary>
        /// <param name="xmlPrivateKey">私钥</param>
        /// <param name="m_strEncryptString">待加密数据</param>
        /// <returns>加密后的数据（Base64）</returns>
        public static string RSAEncryptByPrivateKey(string xmlPrivateKey, string strEncryptString)
        {
            //加载私钥
            RSACryptoServiceProvider privateRsa = new RSACryptoServiceProvider(1024);
            privateRsa.FromXmlString(xmlPrivateKey);

            //转换密钥
            AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetKeyPair(privateRsa);

            IBufferedCipher c = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");// 参数与Java中加密解密的参数一致     
                                                                                  //第一个参数为true表示加密，为false表示解密；第二个参数表示密钥
            c.Init(true, keyPair.Private);
            //byte[] DataToEncrypt = Encoding.UTF8.GetBytes(strEncryptString);

            int index = 0;
            int len = strEncryptString.Length;

            StringBuilder sb = new StringBuilder();
            List<byte> data = new List<byte>();
            while (index < len)
            {
                string temp = "";
                if (index + 117 < len)
                {
                    temp = strEncryptString.Substring(index, index + 117);
                }
                else
                {
                    temp = strEncryptString.Substring(index);
                }

                //加密           
                byte[] encrypted = c.DoFinal(Encoding.UTF8.GetBytes(strEncryptString), index, temp.Length);
                data.AddRange(encrypted);

                //转化为16进制字符串

                index += 117;
            }
            sb.Append(Convert.ToBase64String(data.ToArray()));
            return sb.ToString();
        }


    }
}
