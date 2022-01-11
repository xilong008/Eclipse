// Copyright 2016-2101 Pica.
package com.research.server.mapper.signature;

import org.apache.commons.codec.binary.Hex;

import java.security.*;
import java.security.interfaces.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @ClassName SignatureTest
 * @Description 数字签名测试类（RSA、DSA、ECDSA）
 * @Author Chongwen.jiang
 * @Date 2019/7/29 10:26
 * @ModifyDate 2019/7/29 10:26
 * @Version 1.0
 */
public class SignatureTest {
    public static final String SRC_RSA = "RSA security is security";

    public static final String SRC_DSA = "DSA security is security";

    public static final String SRC_ECDSA = "ECDSA security is security";

    public static void main(String[] args) {
        jdkRSA();

        jdkDSA();

        jdkECDSA();


    }

    /**
     * @Description 用java的jdk里面相关方法实现rsa的签名及签名验证
     * @Author Chongwen.jiang
     * @Date 2019/7/29 10:29
     * @ModifyDate 2019/7/29 10:29
     * @Params []
     * @Return void
     */
    public static void jdkRSA() {
        try {
            // 1.初始化密钥
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(512);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)keyPair.getPrivate();

            // 2.进行签名
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            Signature signature = Signature.getInstance("MD5withRSA");
            signature.initSign(privateKey);
            signature.update(SRC_RSA.getBytes());
            byte[] result = signature.sign();
            System.out.println("jdk rsa sign:" + Hex.encodeHexString(result) );

            // 3.验证签名
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
            keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            signature = Signature.getInstance("MD5withRSA");
            signature.initVerify(publicKey);
            signature.update(SRC_RSA.getBytes());
            boolean bool = signature.verify(result);
            System.out.println("jdk rsa verify:" + bool);
        } catch (Exception e) {
            System.out.println(e.toString());
        }
    }

    /**
     * @Description 用java的jdk里面相关方法实现dsa的签名及签名验证
     * @Author Chongwen.jiang
     * @Date 2019/7/29 10:34
     * @ModifyDate 2019/7/29 10:34
     * @Params []
     * @Return void
     */
    public static void jdkDSA () {
        try {
            // 1.初始化密钥
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
            keyPairGenerator.initialize(512);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            DSAPublicKey dsaPublicKey = (DSAPublicKey)keyPair.getPublic();
            DSAPrivateKey dsaPrivateKey = (DSAPrivateKey)keyPair.getPrivate();

            // 2.进行签名
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(dsaPrivateKey.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("DSA");
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            Signature signature = Signature.getInstance("SHA1withDSA");
            signature.initSign(privateKey);
            signature.update(SRC_DSA.getBytes());
            byte[] result = signature.sign();
            System.out.println("jdk dsa sign:" + Hex.encodeHexString(result) );

            // 3.验证签名
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(dsaPublicKey.getEncoded());
            keyFactory = KeyFactory.getInstance("DSA");
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            signature = Signature.getInstance("SHA1withDSA");
            signature.initVerify(publicKey);
            signature.update(SRC_DSA.getBytes());
            boolean bool = signature.verify(result);
            System.out.println("jdk dsa verify:" + bool);

        } catch (Exception e) {
            System.out.println(e.toString());
        }
    }

    /**
     * @Description 用java的jdk里面相关方法实现ECDSA的签名及签名验证,要jdk7.x以上，ECDSA：椭圆曲线数字签名算法
     * @Author Chongwen.jiang
     * @Date 2019/7/29 10:34
     * @ModifyDate 2019/7/29 10:34
     * @Params []
     * @Return void
     */
    public static void jdkECDSA () {
        try {
            // 1.初始化密钥
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(256);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            ECPublicKey ecPublicKey = (ECPublicKey)keyPair.getPublic();
            ECPrivateKey ecPrivateKey = (ECPrivateKey)keyPair.getPrivate();

            // 2.进行签名
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(ecPrivateKey.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            Signature signature = Signature.getInstance("SHA1withECDSA");
            signature.initSign(privateKey);
            signature.update(SRC_ECDSA.getBytes());
            byte[] result = signature.sign();
            System.out.println("jdk ecdsa sign:" + Hex.encodeHexString(result) );

            // 3.验证签名
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(ecPublicKey.getEncoded());
            keyFactory = KeyFactory.getInstance("EC");
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            signature = Signature.getInstance("SHA1withECDSA");
            signature.initVerify(publicKey);
            signature.update(SRC_ECDSA.getBytes());
            boolean bool = signature.verify(result);
            System.out.println("jdk ecdsa verify:" + bool);
        } catch (Exception e) {
            System.out.println(e.toString());
        }
    }

}

