package com.research.server.mapper.message_digest;

import java.security.MessageDigest;
import java.security.Security;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;

/**
 * @Description SHA算法实现测试类
 * @Author Chongwen.jiang
 * @Date 2019/7/29 15:04
 * @ModifyDate 2019/7/29 15:04
 * @Params 
 * @Return 
 */
public class SHATest {
    public static final String src = "sha test";

    public static void main(String[] args) {
        jdkSHA1();
        bcSHA1();
        bcSHA224();
        bcSHA224b();
        generateSha256();
        ccSHA1();

    }

    /**
     * @Description 用jdk实现:SHA1
     * @Author Chongwen.jiang
     * @Date 2019/7/29 10:56
     * @ModifyDate 2019/7/29 10:56
     * @Params []
     * @Return void
     */
    public static void jdkSHA1() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA");
            md.update(src.getBytes());
            System.out.println("jdk sha-1:" + Hex.encodeHexString(md.digest()));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * @Description 用bouncy castle实现:SHA1
     * @Author Chongwen.jiang
     * @Date 2019/7/29 10:56
     * @ModifyDate 2019/7/29 10:56
     * @Params []
     * @Return void
     */
    public static void bcSHA1() {

        Digest digest = new SHA1Digest();
        digest.update(src.getBytes(), 0, src.getBytes().length);
        byte[] sha1Bytes = new byte[digest.getDigestSize()];
        digest.doFinal(sha1Bytes, 0);
        System.out.println("bc sha-1:" + org.bouncycastle.util.encoders.Hex.toHexString(sha1Bytes));
    }


    /**
     * @Description 用bouncy castle实现:SHA224
     * @Author Chongwen.jiang
     * @Date 2019/7/29 10:56
     * @ModifyDate 2019/7/29 10:56
     * @Params []
     * @Return void
     */
    public static void bcSHA224() {

        Digest digest = new SHA224Digest();
        digest.update(src.getBytes(), 0, src.getBytes().length);
        byte[] sha224Bytes = new byte[digest.getDigestSize()];
        digest.doFinal(sha224Bytes, 0);
        System.out.println("bc sha-224:" + org.bouncycastle.util.encoders.Hex.toHexString(sha224Bytes));
    }

    /**
     * @Description 用bouncy castle与jdk结合实现:SHA224
     * @Author Chongwen.jiang
     * @Date 2019/7/29 10:56
     * @ModifyDate 2019/7/29 10:56
     * @Params []
     * @Return void
     */
    public static void bcSHA224b() {

        try {
            Security.addProvider(new BouncyCastleProvider());
            MessageDigest md = MessageDigest.getInstance("SHA224");
            md.update(src.getBytes());
            System.out.println("bc and JDK sha-224:" + Hex.encodeHexString(md.digest()));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void generateSha256() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            md.update(src.getBytes("UTF-8")); // Change this to "UTF-16" if needed
            byte[] digest = md.digest();
            BigInteger bigInt = new BigInteger(1, digest);
            System.out.println("Sha256 hash: " + bigInt.toString(16));
        } catch (Exception e) {
            System.out.println(e.toString());
        }

    }

    /**
     * @Description 用common codes实现实现:SHA1
     * @Author Chongwen.jiang
     * @Date 2019/7/29 10:57
     * @ModifyDate 2019/7/29 10:57
     * @Params []
     * @Return void
     */
    public static void ccSHA1() {
        System.out.println("common codes SHA1 - 1 :" + DigestUtils.sha1Hex(src.getBytes()));
        System.out.println("common codes SHA1 - 2 :" + DigestUtils.sha1Hex(src));
    }


}

