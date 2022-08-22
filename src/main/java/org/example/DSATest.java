package org.example;

import sun.misc.BASE64Decoder;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.StringReader;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
/**
 * 以下命令生成的文件会存放在当前目录下
 * -- 生成随机参数
 * openssl dsaparam -out dsa_param.pem 1024
 * -- 生成DSA私钥 privkey.pem
 * openssl gendsa -out dsa_private_key.pem dsa_param.pem
 * -- 生成DSA公钥 pubkey.pem
 * openssl dsa -in dsa_private_key.pem -pubout -out dsa_public_key.pem
 * -- 对私钥进行pkcs8编码
 * openssl pkcs8 -topk8 -in dsa_private_key.pem -out pkcs8_dsa_private_key.pem -nocrypt
 * */
public class DSATest {
    private static final String PRIVATE_KEY_PEM = "/Users/j/Desktop/dsa/pkcs8_dsa_private_key.pem";
    private static final String PUBLIC_KEY_PEM = "/Users/j/Desktop/dsa/dsa_public_key.pem";
    private static final String PRIVATE_KEY_PKCS8 = "-----BEGIN PRIVATE KEY-----\n" +
            "MIIBSgIBADCCASsGByqGSM44BAEwggEeAoGBAMNUsRMfJ32hCOnjO3UpEeEjebnp\n" +
            "GBsQmawr5PzZgmNrfgKJlzHD44qL9qlMhua8xH7dRCqpcxbnuCd+g5jLVQ1KOwR6\n" +
            "0h7vlLt3YY7wZJyArFgiEi7+j8rkQWhaSJD3TbqMRb7EVJgRVtLv5GNM5YhA30hB\n" +
            "iwOxOANrEZKMotjzAhUAi12iG05Clv5yhb1jLnS/GJaBR5MCgYALDQ14AKCUpxYL\n" +
            "CouahuvpNSNlHOTN8mZi4NUw590XZRJSUHMra3xMbeq4NcUEhq0+vZf8LpWI6rgk\n" +
            "CzVXk9hFPIpqrUscHtb3llecYRvuyifyjtYiGyhYBLn1qzrqIQpyarEGg8KzT6Lt\n" +
            "3d8shwfyrFrPp6613HL31iqo+v35gQQWAhQiBsB/8T/VYj+3czgdvmmjOWsZ1g==\n" +
            "-----END PRIVATE KEY-----\n";//测试生成的DSA私钥
    private static final String PUBLIC_KEY_STRING
            = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBtzCCASsGByqGSM44BAEwggEeAoGBAMNUsRMfJ32hCOnjO3UpEeEjebnpGBsQ\n" +
            "mawr5PzZgmNrfgKJlzHD44qL9qlMhua8xH7dRCqpcxbnuCd+g5jLVQ1KOwR60h7v\n" +
            "lLt3YY7wZJyArFgiEi7+j8rkQWhaSJD3TbqMRb7EVJgRVtLv5GNM5YhA30hBiwOx\n" +
            "OANrEZKMotjzAhUAi12iG05Clv5yhb1jLnS/GJaBR5MCgYALDQ14AKCUpxYLCoua\n" +
            "huvpNSNlHOTN8mZi4NUw590XZRJSUHMra3xMbeq4NcUEhq0+vZf8LpWI6rgkCzVX\n" +
            "k9hFPIpqrUscHtb3llecYRvuyifyjtYiGyhYBLn1qzrqIQpyarEGg8KzT6Lt3d8s\n" +
            "hwfyrFrPp6613HL31iqo+v35gQOBhQACgYEAoEh8mAJgO5rOuk9nthZwLILTZF6J\n" +
            "DhGFVRdgmU3Q2lD2b6b0g667D2z4L7Ojk7eWpfB1AapD+jTCbZrasl2UfKn4F9Ua\n" +
            "xQXb4zui2lpIYURjpLLf48I6Kjuq0VVKZzDi+iIs1m1FQO2eInfRMUNPoOlNJXsi\n" +
            "a6GlheOukVAfdks=\n" +
            "-----END PUBLIC KEY-----\n";

    public static void main(String[] args) throws Exception {
//        PrivateKey privateKey = getPrivateKeyFromPem();
//        PublicKey publicKey = getPublicKeyFromPem();
        PrivateKey privateKey = getPrivateKeyFromString();
        PublicKey publicKey = getPublickKeyFromString();
        String message = "hello world";
        byte[] signMessage = signMessage(privateKey, message.getBytes());
        boolean result = verifySignature(publicKey, message.getBytes(), signMessage);
        System.out.println(result);
    }

    // 获取私匙 from pem file
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
    // 获取私匙 from string
    private static PrivateKey getPrivateKeyFromString() throws Exception {
        BufferedReader br = new BufferedReader(new StringReader(PRIVATE_KEY_PKCS8));
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

    // 获取公钥 from pem file
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
    // 获取公钥 from string
    private static PublicKey getPublickKeyFromString() throws Exception {
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

