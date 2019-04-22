using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AESAndRSATest
{
    class Program
    {
        static void Main(string[] args)
        {
            //测试 AES 
            //加密
            string aesKey = "87783272bf0b42b9";
            string aesIV = "b6f262e1cf2a4ca2";
            string content = "{\"orderNo\":\"order1552809255\",\"subject\":\"重庆火锅\",\"amount\":\"100\",\"notifyUrl\":\"http %3A%2F%2Fdemo-php%2Fnotice%2Fpay.php\",\"payType\":\"0\",\"source\":\"ZFBZF\"}";
            string enstr = AESHelper.AES_Encrypt(content, aesKey, aesIV);

            //解密
           // string destr = "hm9RsISvoHwKz30NeRAEt3ykTR0l0mJ2xyfl3AOr9/sVIvAwGNKGL2EtFiOWJNAbTnb7IDn+qmicXoQXR+rtlo0f78ifI6T0RQmfn7BLYVUTmSDOlW+ymXsaKNbpZDpLZG3SpxNm4Rqv7E2Ca7KmFHjZXI1Nlto4zwiD4E5MWuJZ/NFXtAQfF+M68rT/fnkLGGE+Zlq0y8rjP9EkXDfl+A==";
            content = AESHelper.AES_Decrypt(enstr, aesKey, aesIV);

            //测试 RSA
            RSAHelper rsa = new RSAHelper();
            string contentRsa = "你好rsa";
            string pubKey = @"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs459yAKeu4oMw0NiR38SIx9T1hObitw3G7wRRJlIwt9Yl6lKYDDwjqhW3J2bXMZwfPhfDkGRZW40M+7TQ0eFbnXAp8rRD4IzIJ4uMbwWOb9htxsLEyb9RGyeC8qQsctZ/kRAmf5FMigNJXkXwFPNnBSUy/XNitsf1J4XPuFibRs6O2AKLQDfry3NEPi6U6ibbdJAeTO/0Ey86O/+9P2dkexr8k+R+klWAsCXfh1+YAiFufiUx9QiqxXxqzC6cT4h5EcQHtgIjI4BwAT/lbjJc3RmPwp5OoQiP3n6UmW5fsOwBUaIADytoRM7DxRKf9g4Udh2IqySt53p1/DkQI9cYwIDAQAB";
            string priKey = @"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCzjn3IAp67igzDQ2JHfxIjH1PWE5uK3DcbvBFEmUjC31iXqUpgMPCOqFbcnZtcxnB8+F8OQZFlbjQz7tNDR4VudcCnytEPgjMgni4xvBY5v2G3GwsTJv1EbJ4LypCxy1n+RECZ/kUyKA0leRfAU82cFJTL9c2K2x/Unhc+4WJtGzo7YAotAN+vLc0Q+LpTqJtt0kB5M7/QTLzo7/70/Z2R7GvyT5H6SVYCwJd+HX5gCIW5+JTH1CKrFfGrMLpxPiHkRxAe2AiMjgHABP+VuMlzdGY/Cnk6hCI/efpSZbl+w7AFRogAPK2hEzsPFEp/2DhR2HYirJK3nenX8ORAj1xjAgMBAAECggEAU6aaqsets6lI8N8/thdZF8vMfvt7h2G4us8PLGpNH5x15ZIU+GNUbuG2NemnK723QkFj53xchGinIVquSbXUT/XD32f5pcP+lb+bvcfmgtjKaUfMDQwpCeugZdXlOy+FqZOalSOEkS1fkomrqwpfy8s61xqYu4wCdEeChOTzueghEX+qHZ3trb+/13rvUGwVma80edbn/qQvc87aZJ+3+p8vmxJjaoqT6gE5BrH+ZZoeL3GhK/c3FEuTfJd9CrdLKTjBeAyKTvCvk093VosRQpVYLeAlQ1V6ZMdgvMPV4Q2g1pPuJsiwYxWxjajWV3+qWCcyer5aD2xr0v/Q2JlfgQKBgQDnB/7wTlElybA49PYipZ5vuUvSwOSH7Nn3dCSpNT9GxdJ9bu3exVax93lp6USPni/+IOhCZajHGvWqNliIupYCMeL6B5EfG7xhP66+RpNrw+ksNEOv4wtHIXBJd57eycMeOKIfrjIl5vgGbCRkBM88wzV1NsRa2k5i36iEBmoVcQKBgQDG9lU7TA4tPQOnCBk1Jhzm3oI32SYeQIQxnkMdxwmHCieYxQiRMN94PN9AB0F2l4QMOtr9hHnhJrnA5fH4vxsLeABAvskOK3gxJzujBhQpjYwkhFFO3PdZVm9VZMiCU073hSpA/ZExzZMiXQXNDjgWwiwwGBIIule3ieBw7QWVEwKBgQDBVEWYXlE1p/NZllOqZqGQqKS0tkoHHMLBemV7W12aIcykvoE7nDOSNZ9aa6O98wgCRxNVDLER/JN7XoLz1//T0l84D8D3IUSgtKPMAk83LPggz5OcyggT+/103S8LDBfFYGr6y9CXOxJufWxubj/lfw1rCuuBg5F41+SyppN7YQKBgQC3ayYd2TqEh+gTFwsuDSm9yEkhtUVHxFBZ8b2L+Q6WeE0SsCn6t6R8Exn4y/eUnY+1Opjh+DvnzayW4SUWHQ+QnhsVlQyCzJ4sKi/3VUZHHF+i1nyiiGBa8q0GezfBtY1p8FCIw3oUAKFwn3MWm9InYPAdkkMl2qu83xWS5V8tEwKBgFpY5GpgiS4KVzYeFLqsAdiuOwElmT4dfmAfhWL6IJuLNBkW67yUhiGHzWIP9CyC4Bs6hk0SSvI+W1cvbRoj7sj4imi/lGsl3TZ93fVme67HR8VI5hJDlagezNLCR3hOZvULxo3wr88c2O5ZKwXeJML4kPVS89Oq3IeVkg3wWRlo";
            enstr =  rsa.RsaPubEncrypt(contentRsa, pubKey);

            var contentRsa1 = rsa.RsaPriDecrypt("QjBGRTAwOUZCREQ1MUEyNTgwQzNGN0ZDRDBEOEY0NEQ2NkI2QzJERjQwRTI2MTZFQzA2N0IyQjJGREMxNzBFRjVCMDgwNjM3RTAyMEU5Q0I2OURBMUUyNjM1QjMxQTVBMDgyMEY2Q0Y3MERGREI2MEFBRkQ5OUMxOThCOEZGRDFCM0NBMkFGNURCRDg1NTBFMjBDODlDRDQ1M0VERjVCOUQ3NzQ3NTg1OUE0NEY5MDJGOUExNEIwMUVERTBFRUFCOEI1QkI4N0RCRTY3MTcxMkYwRTEwOUFBMTg3REFFQkM5NzAxODFCRTUzMUQ0NDQ2RjY1MTg3QUZBQ0IwM0FFOTFFNURGMUY5MkY3RERCMzVFNjJBMTZDQzhFN0I2MUFEMDYzODdDOTMyRjdFOUQyQjJFRkM0OEVBQ0E2QjQ1NDNEMUIwNEVDQTUyMEI5RDRDRDY2MEEyODY2MkIwNTBBQTZGRkRDMDg0QTU4RDFDQTUxMTA3MEQ4OTQ0QUNCRkZERkVGRUEzNzIyM0VBNjJFRjE1MjFERTMxRDg0NEI2Q0ZGREFDN0Q0RTU5MDRGQTRDMjUwMTA0OUYyMDU2NUM0REEzMDk5NkFGNDUyMUZCREI1RTFFNTcwRDMwMkQ0QUE4MDFGMDU2REQ2RTQ2OUZEQzhERkZCMEM4MkQ0NzY0OTM=", priKey);


            //测试 签名
            //使用私钥生成签名
            var signRst = rsa.Sign(contentRsa, priKey);
            //使用公钥验证签名
            var isSign = rsa.Verify("06FX0qCJuJjgriYv","HC4ojHLqS0876Vv8QMPxX2R/cFYu9wtiYwle8hnOMxZkZLU+8cujzD3LzJRHzvcxHceHpzoBJE/xRtKJMZx9e9r5Tci6C+tFLWSq6A6JNLGaw9DzbaSPaeAmrrxrSlwUnQwrDBqCnwDlLUhky0pVfC64pWV7osFCbCKtasSz1zFlpvgXLKg8a0yN6ocH8RFyjSmaF87y2ol9Ze1dmg5UKICNwc5Y9iMzx+A5POczpZApKhu5KD9AANYLjmXPSvZADMuKAl443xtQ01Xdn18mTgIWZXCW1t4BloxNXL3WOFH68eZmKKPAF78VBeiEd3b93rCAa3T/em3GwJ8V4zKA9Q==", pubKey);

            Console.ReadLine();
        }
    }
}
