package com.research.server.mapper.symmetric_encryption;

import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @Description DES3算法实现测试类
 * @Author Chongwen.jiang
 * @Date 2019/7/29 15:07
 * @ModifyDate 2019/7/29 15:07
 * @Params
 * @Return
 */
public class DES3Test {
    public static final String src = "3des test";

    public static void main(String[] args) {
        jdk3DES();
        bc3DES();

    }

    /**
     * @Description 用jdk实现DES3加解密
     * @Author Chongwen.jiang
     * @Date 2019/7/29 10:39
     * @ModifyDate 2019/7/29 10:39
     * @Params
     * @Return
     */
    public static void jdk3DES() {
        try {
            // 生成KEY
            KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
            // 必须长度是：112或168
            // keyGenerator.init(168);
            keyGenerator.init(new SecureRandom());
            // 产生密钥
            SecretKey secretKey = keyGenerator.generateKey();
            // 获取密钥
            byte[] bytesKey = secretKey.getEncoded();

            // KEY转换
            DESedeKeySpec desKeySpec = new DESedeKeySpec(bytesKey);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
            Key convertSecretKey = factory.generateSecret(desKeySpec);

            // 加密
            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, convertSecretKey);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("jdk 3des encrypt:" + Hex.encodeHexString(result));

            // 解密
            cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);
            result = cipher.doFinal(result);
            System.out.println("jdk 3des decrypt:" + new String(result));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * @Description 用bouncy castle实现DES3加解密
     * @Author Chongwen.jiang
     * @Date 2019/7/29 10:40
     * @ModifyDate 2019/7/29 10:40
     * @Params
     * @Return
     */
    public static void bc3DES() {
        try {
            Security.addProvider(new BouncyCastleProvider());

            // 生成KEY
            KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede", "BC");
            keyGenerator.getProvider();
            keyGenerator.init(168);
            // 产生密钥
            SecretKey secretKey = keyGenerator.generateKey();
            // 获取密钥
            byte[] bytesKey = secretKey.getEncoded();

            // KEY转换
            DESedeKeySpec desKeySpec = new DESedeKeySpec(bytesKey);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
            Key convertSecretKey = factory.generateSecret(desKeySpec);

            // 加密
            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, convertSecretKey);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("bc 3des encrypt:" + Hex.encodeHexString(result));

            // 解密
            cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);
            result = cipher.doFinal(result);
            System.out.println("bc 3des decrypt:" + new String(result));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}

