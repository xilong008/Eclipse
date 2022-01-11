package com.research.server.mapper.symmetric_encryption;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.codec.binary.Hex;

/**
 * @Description PBE算法实现测试类
 * @Author Chongwen.jiang
 * @Date 2019/7/29 15:08
 * @ModifyDate 2019/7/29 15:08
 * @Params
 * @Return
 */
public class PBETest {
    public static final String src = "pbe test";

    public static void main(String[] args) {
        jdkPBE();

    }

    /**
     * @Description 用jdk实现PBE加解密
     * @Author Chongwen.jiang
     * @Date 2019/7/29 10:44
     * @ModifyDate 2019/7/29 10:44
     * @Params []
     * @Return void
     */
    public static void jdkPBE() {
        try {
            // 初始化盐
            SecureRandom random = new SecureRandom();
            byte[] salt = random.generateSeed(8);

            // 口令与密钥
            String password = "timliu";
            PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWITHMD5andDES");
            Key key = factory.generateSecret(pbeKeySpec);

            // 加密
            PBEParameterSpec pbeParameterSpac = new PBEParameterSpec(salt, 100);
            Cipher cipher = Cipher.getInstance("PBEWITHMD5andDES");
            cipher.init(Cipher.ENCRYPT_MODE, key, pbeParameterSpac);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("jdk pbe encrypt:" + Hex.encodeHexString(result));

            // 解密
            cipher.init(Cipher.DECRYPT_MODE, key, pbeParameterSpac);
            result = cipher.doFinal(result);
            System.out.println("jdk pbe decrypt:" + new String(result));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


}

