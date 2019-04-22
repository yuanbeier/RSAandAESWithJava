using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AESAndRSATest
{
    public class AESHelper
    {
        /// <summary>
        /// AES解密
        /// </summary>
        /// <param name="decryptString">AES密文</param>
        /// <param name="key">秘钥（44个字符）</param>
        /// <param name="ivString">向量（16个字符）</param>
        /// <returns></returns>
        public static string AES_Decrypt(string decryptString, string key, string ivString)
        {
            try
            {
                RijndaelManaged aes = new RijndaelManaged();

                byte[] iv = Encoding.UTF8.GetBytes(ivString.Substring(0, 16));
                aes.Key = Encoding.UTF8.GetBytes(key.Substring(0, 16));
                aes.Mode = CipherMode.CBC;
                aes.IV = iv;
                aes.Padding = PaddingMode.None;  //


                ICryptoTransform rijndaelDecrypt = aes.CreateDecryptor();
                byte[] inputData = Convert.FromBase64String(decryptString);
                byte[] xBuff = rijndaelDecrypt.TransformFinalBlock(inputData, 0, inputData.Length);
                //去掉多余空格
                return Encoding.UTF8.GetString(xBuff).Trim();
            }
            catch (Exception ex)
            {
                throw;

            }
        }



        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="encriyptString">要被加密的字符串</param>
        /// <param name="key">秘钥（44个字符）</param>
        /// <param name="ivString">向量长度（16个字符）</param>
        /// <returns></returns>
        public static string AES_Encrypt(string encriyptString, string key, string ivString)
        {
            SymmetricAlgorithm aes = new RijndaelManaged();

            byte[] iv = Encoding.UTF8.GetBytes(ivString.Substring(0, 16));


            aes.Key = Encoding.UTF8.GetBytes(key.Substring(0, 16));
            aes.Mode = CipherMode.CBC;
            aes.IV = iv;
            aes.Padding = PaddingMode.None; //


            ICryptoTransform rijndaelEncrypt = aes.CreateEncryptor();
            byte[] inputData = Encoding.UTF8.GetBytes(encriyptString);
            //进行补位
            int mod = (8 - (inputData.Length % 8));
            for(int i = 0;i < mod;i++)
            {
                encriyptString =  encriyptString + " ";
            }
            inputData = Encoding.UTF8.GetBytes(encriyptString);
            byte[] encryptedData = rijndaelEncrypt.TransformFinalBlock(inputData, 0, inputData.Length);

            return Convert.ToBase64String(encryptedData);
        }

    }
}

