package com.research.server.mapper.symmetric_encryption;

import java.security.Key;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @Description AES算法测试类
 * @Author Chongwen.jiang
 * @Date 2019/7/29 15:07
 * @ModifyDate 2019/7/29 15:07
 * @Params
 * @Return
 */
public class AESTest {
    public static final String src = "aes test";

    public static void main(String[] args) {
        jdkAES();
        bcAES();

    }

    /**
     * @Description 用jdk实现
     * @Author Chongwen.jiang
     * @Date 2019/7/29 15:09
     * @ModifyDate 2019/7/29 15:09
     * @Params []
     * @Return void
     */
    public static void jdkAES() {
        try {
            // 生成KEY
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            // 产生密钥
            SecretKey secretKey = keyGenerator.generateKey();
            // 获取密钥
            byte[] keyBytes = secretKey.getEncoded();

            // KEY转换
            Key key = new SecretKeySpec(keyBytes, "AES");

            // 加密
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("jdk aes encrypt:" + Hex.encodeHexString(result));

            // 解密
            cipher.init(Cipher.DECRYPT_MODE, key);
            result = cipher.doFinal(result);
            System.out.println("jdk aes decrypt:" + new String(result));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * @Description 用bouncy castle实现
     * @Author Chongwen.jiang
     * @Date 2019/7/29 15:09
     * @ModifyDate 2019/7/29 15:09
     * @Params []
     * @Return void
     */
    public static void bcAES() {
        try {
            Security.addProvider(new BouncyCastleProvider());

            // 生成KEY
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
            keyGenerator.getProvider();
            keyGenerator.init(128);
            // 产生密钥
            SecretKey secretKey = keyGenerator.generateKey();
            // 获取密钥
            byte[] keyBytes = secretKey.getEncoded();

            // KEY转换
            Key key = new SecretKeySpec(keyBytes, "AES");

            // 加密
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("bc aes encrypt:" + Hex.encodeHexString(result));

            // 解密
            cipher.init(Cipher.DECRYPT_MODE, key);
            result = cipher.doFinal(result);
            System.out.println("bc aes decrypt:" + new String(result));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}

