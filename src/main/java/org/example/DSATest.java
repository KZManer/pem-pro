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

public class DSATest {
    private static final String PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n" +
            "MIIBSgIBADCCASsGByqGSM44BAEwggEeAoGBAMNUsRMfJ32hCOnjO3UpEeEjebnp\n" +
            "GBsQmawr5PzZgmNrfgKJlzHD44qL9qlMhua8xH7dRCqpcxbnuCd+g5jLVQ1KOwR6\n" +
            "0h7vlLt3YY7wZJyArFgiEi7+j8rkQWhaSJD3TbqMRb7EVJgRVtLv5GNM5YhA30hB\n" +
            "iwOxOANrEZKMotjzAhUAi12iG05Clv5yhb1jLnS/GJaBR5MCgYALDQ14AKCUpxYL\n" +
            "CouahuvpNSNlHOTN8mZi4NUw590XZRJSUHMra3xMbeq4NcUEhq0+vZf8LpWI6rgk\n" +
            "CzVXk9hFPIpqrUscHtb3llecYRvuyifyjtYiGyhYBLn1qzrqIQpyarEGg8KzT6Lt\n" +
            "3d8shwfyrFrPp6613HL31iqo+v35gQQWAhQiBsB/8T/VYj+3czgdvmmjOWsZ1g==\n" +
            "-----END PRIVATE KEY-----\n";//测试生成的DSA私钥
    private static final String PRIVATE_KEY_PEM = "/Users/j/Desktop/dsa/pkcs8_dsa_private_key.pem";
    private static final String PUBLIC_KEY_PEM = "/Users/j/Desktop/dsa/dsa_public_key.pem";

    public static void main(String[] args) throws Exception {
        PrivateKey privateKey = getPrivateKeyFromPem();
//        PrivateKey privateKey = getPrivateKeyFromString();
        PublicKey publicKey = getPublicKeyFromPem();
        String message = "hello world";
        byte[] signMessage = signMessage(privateKey, message.getBytes());
        boolean result = verifySignature(publicKey, message.getBytes(), signMessage);
        System.out.println(result);
    }

    // 获取私匙（通过pem文件）
    private static PrivateKey getPrivateKeyFromPem() throws Exception {
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

        // 生成私匙
        KeyFactory kf = KeyFactory.getInstance("DSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(b);
        PrivateKey privateKey = kf.generatePrivate(keySpec);
        return privateKey;
    }
    // 获取私匙（通过字符串）
    private static PrivateKey getPrivateKeyFromString() throws Exception {
        BufferedReader br = new BufferedReader(new StringReader(PRIVATE_KEY));
        String s = br.readLine();
        String str = "";
        s = br.readLine();
        while (s.charAt(0) != '-') {
            str += s + "\r";
            s = br.readLine();
        }
        BASE64Decoder base64decoder = new BASE64Decoder();
        byte[] b = base64decoder.decodeBuffer(str);

        // 生成私匙
        KeyFactory kf = KeyFactory.getInstance("DSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(b);
        PrivateKey privateKey = kf.generatePrivate(keySpec);
        return privateKey;
    }

    // 获取公钥
    private static PublicKey getPublicKeyFromPem() throws Exception {
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
        KeyFactory kf = KeyFactory.getInstance("DSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(b);
        PublicKey pubKey = kf.generatePublic(keySpec);
        return pubKey;
    }

    /**
     * 签名信息
     * @param privateKey
     * @param message
     * @return
     */
    private static byte[] signMessage(PrivateKey privateKey, byte[] message) {

        Signature dsa;
        try {
            dsa = Signature.getInstance("SHA1withDSA", "SUN");
            dsa.initSign(privateKey);
            dsa.update(message);
            byte[] result = dsa.sign();
            return result;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 验证签名数据
     * @param pubKey
     * @param message
     * @param signature
     * @return
     */
    private static boolean verifySignature(PublicKey pubKey, byte[] message, byte[] signature) {
        Signature dsa;
        try {
            dsa = Signature.getInstance("SHA1withDSA", "SUN");
            dsa.initVerify(pubKey);
            dsa.update(message);
            return dsa.verify(signature);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
}

