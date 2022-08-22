package org.example;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * 以下命令生成的文件会存放在当前目录下
 * -- 生成私钥命令
 * openssl genrsa -out rsa_private_key.pem 1024
 * -- 生成公钥命令
 * openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem
 * -- 对私钥进行pkcs8编码
 * openssl pkcs8 -topk8 -in rsa_private_key.pem -out pkcs8_rsa_private_key.pem -nocrypt
 */
public class RSATest {
    public static final String PRIVATE_KEY_PEM = "/Users/j/Desktop/rsa/pkcs8_rsa_private_key.pem";
    public static final String PUBLIC_KEY_PEM = "/Users/j/Desktop/rsa/ras_public_key.pem";
    public static final String PRIVATE_KEY_PCKS8
            = "-----BEGIN PRIVATE KEY-----\n" +
            "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMZbTbPEN3jtzla3\n" +
            "Ls/a2HDYN/bif0BujgHmllWDjwEoAqFDZrgpI17Y3xY6jMFs5amY77vg3K19obCl\n" +
            "ScVM1Y4eYsMhyxHzuF3uju2Xd891BIeHSdHDtWQ6JqVUUndyEYrkfNv+dCA7I47/\n" +
            "l5hH1hYgGnQ3d7AVtyvvL9NFT3AnAgMBAAECgYEAvo9ewdJC/LFxpstLdLKpdxey\n" +
            "BEQqvkq3sMnHKZY/H3xBso2fNFOJQIiXIbLUIMsuhFWCEvv+5cmpOZxBmAOtsK5c\n" +
            "cLF7VP3D5Ix1q4Cg9MYl1eabYkkHKd3lfsWQwMPZgEbLCOpMZwtMUIGTgpNtVy5f\n" +
            "iusbXikkycrGib5rUbkCQQDv2dEQOIZ2SGe0iY+FB1drhXNliAqAjhuVkz+GC+E8\n" +
            "hQEPbeIsxgusElfKzDPZdrvoMzVmzq4qDiBdMrNniwFzAkEA07ZF8lhrWx3cFK2H\n" +
            "lbNP/IokXZp27bJBnddLEk5Z+yK3R+nyqVoesUwqWqDvNmE6evLnztdtlAiyxTkk\n" +
            "BqaZfQJAY4gEFbMfOV56ipS7Ff0h7eCHLo7xrL9L+xoLtlifszmOYxS6UtIsbc9+\n" +
            "1w0+RvParlTxyCPkaldKXuJ3SHSKuQJAX2DNkEmfS/Re0v3+iEW5Mke17GmLTLiy\n" +
            "8P4uNvgPd6GDOqW+CeeszilHJ387ZZ9V7lACeN/64OcuSsXcYhaqLQJAVxEBN0d3\n" +
            "pI5fixHw8Bahw4N2lIq+poXHNRHjkdO+6Qwe6Y9TBn0rtAaqZD3adX5pQcKUUP/C\n" +
            "xg/EwCxcMeC84A==\n" +
            "-----END PRIVATE KEY-----\n";
    public static final String PUBLIC_KEY_STRING
            = "-----BEGIN PUBLIC KEY-----\n" +
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDGW02zxDd47c5Wty7P2thw2Df2\n" +
            "4n9Abo4B5pZVg48BKAKhQ2a4KSNe2N8WOozBbOWpmO+74NytfaGwpUnFTNWOHmLD\n" +
            "IcsR87hd7o7tl3fPdQSHh0nRw7VkOialVFJ3chGK5Hzb/nQgOyOO/5eYR9YWIBp0\n" +
            "N3ewFbcr7y/TRU9wJwIDAQAB\n" +
            "-----END PUBLIC KEY-----\n";

    public static final String KEY_SHA = "SHA";
    public static final String KEY_MD5 = "MD5";
    public static final String KEY_ALGORITHM = "RSA";
    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

    public static void main(String[] args) throws Exception {
        PrivateKey privateKey = getPrivateKeyFromPem();
//        PublicKey publicKey = getPublicKeyFromPem();
//        PrivateKey privateKey = getPrivateKeyFromString();
        PublicKey publicKey = getPublicKeyFromString();
        String data = "hello world";

        /*************************************************************************************************/
        //私钥加密
        byte[] privateDataBytes = encryptByPrivateKey(data.getBytes(StandardCharsets.UTF_8), privateKey);
        String privateDataBase64 = encryptBASE64(privateDataBytes);
        System.out.println(privateDataBase64);
        //公钥解密
        privateDataBytes = decryptBASE64(privateDataBase64);
        byte[] dataBytes = decryptByPublicKey(privateDataBytes, publicKey);
        System.out.println(new String(dataBytes, StandardCharsets.UTF_8));
        /*************************************************************************************************/

        /*************************************************************************************************/
        //公钥加密
        byte[] publicDataBytes = encryptByPublicKey(data.getBytes(StandardCharsets.UTF_8), publicKey);
        String publicDataBase64 = encryptBASE64(publicDataBytes);
        System.out.println(publicDataBase64);
        //私钥解密
        publicDataBytes = decryptBASE64(publicDataBase64);
        dataBytes = decryptByPrivateKey(publicDataBytes, privateKey);
        System.out.println(new String(dataBytes, StandardCharsets.UTF_8));
        /*************************************************************************************************/

        /*************************************************************************************************/
        //签名：私钥加密
        String sign = sign(data.getBytes(StandardCharsets.UTF_8), privateKey);
        System.out.println(sign);
        //验证签名：公钥解密
        boolean verify = verify(data.getBytes(StandardCharsets.UTF_8), publicKey, sign);
        System.out.println(verify);
        /*************************************************************************************************/
    }

    /**
     * 用私钥对信息生成数字签名
     *
     * @param data       加密数据
     * @param privateKey 私钥
     * @return
     * @throws Exception
     */
    public static String sign(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(data);
        return encryptBASE64(signature.sign());
    }

    /**
     * 校验数字签名
     *
     * @param data      加密数据
     * @param publicKey 公钥
     * @param sign      数字签名
     * @return 校验成功返回true 失败返回false
     * @throws Exception
     */
    public static boolean verify(byte[] data, PublicKey publicKey, String sign) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(decryptBASE64(sign));
    }

    /**
     * 私钥解密
     *
     * @param data       密文
     * @param privateKey 私钥
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] data, PrivateKey privateKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    /**
     * 用公钥解密
     *
     * @param data      密文
     * @param publicKey 公钥
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPublicKey(byte[] data, PublicKey publicKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    /**
     * 用公钥加密
     *
     * @param data      明文
     * @param publicKey 公钥
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(byte[] data, PublicKey publicKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    /**
     * 用私钥加密
     *
     * @param data       明文
     * @param privateKey 私钥
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPrivateKey(byte[] data, PrivateKey privateKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    // 获取私匙 from pem file
    public static PrivateKey getPrivateKeyFromPem() throws Exception {
        BufferedReader br = new BufferedReader(new FileReader(PRIVATE_KEY_PEM));
        String s = br.readLine();
        String str = "";
        s = br.readLine();
        while (s.charAt(0) != '-') {
            str += s + "\r";
            s = br.readLine();
        }
        BASE64Decoder base64decoder = new BASE64Decoder();
        byte[] b = base64decoder.decodeBuffer(str);

        //生成私钥
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(b);
        PrivateKey privateKey = kf.generatePrivate(keySpec);
        return privateKey;
    }

    //获取私钥 from string
    public static PrivateKey getPrivateKeyFromString() throws Exception {
        BufferedReader br = new BufferedReader(new StringReader(PRIVATE_KEY_PCKS8));
        String s = br.readLine();
        String str = "";
        s = br.readLine();
        while (s.charAt(0) != '-') {
            str += s + "\r";
            s = br.readLine();
        }
        BASE64Decoder base64Decoder = new BASE64Decoder();
        byte[] b = base64Decoder.decodeBuffer(PRIVATE_KEY_PCKS8);

        //生成私钥
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(b);
        PrivateKey privateKey = kf.generatePrivate(keySpec);
        return privateKey;
    }

    // 获取公钥 from pem file
    public static PublicKey getPublicKeyFromPem() throws Exception {
        BufferedReader br = new BufferedReader(new FileReader(PUBLIC_KEY_PEM));
        String s = br.readLine();
        String str = "";
        s = br.readLine();
        while (s.charAt(0) != '-') {
            str += s + "\r";
            s = br.readLine();
        }
        BASE64Decoder base64decoder = new BASE64Decoder();
        byte[] b = base64decoder.decodeBuffer(str);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(b);
        PublicKey pubKey = kf.generatePublic(keySpec);
        return pubKey;
    }
    //获取公钥 from string
    public static PublicKey getPublicKeyFromString() throws Exception {
        BufferedReader br = new BufferedReader(new StringReader(PUBLIC_KEY_STRING));
        String s = br.readLine();
        String str = "";
        s = br.readLine();
        while (s.charAt(0) != '-') {
            str += s + "\r";
            s = br.readLine();
        }
        BASE64Decoder base64decoder = new BASE64Decoder();
        byte[] b = base64decoder.decodeBuffer(str);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(b);
        PublicKey pubKey = kf.generatePublic(keySpec);
        return pubKey;
    }

    public static byte[] decryptBASE64(String key) throws Exception {
        return (new BASE64Decoder()).decodeBuffer(key);
    }

    public static String encryptBASE64(byte[] key) throws Exception {
        return (new BASE64Encoder()).encodeBuffer(key);
    }

    public static byte[] encryptMD5(byte[] data) throws Exception {
        MessageDigest md5 = MessageDigest.getInstance(KEY_MD5);
        md5.update(data);
        return md5.digest();
    }

    public static byte[] encryptSHA(byte[] data) throws Exception {
        MessageDigest sha = MessageDigest.getInstance(KEY_SHA);
        sha.update(data);
        return sha.digest();
    }
}
