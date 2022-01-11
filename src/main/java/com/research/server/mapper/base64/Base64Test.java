package com.research.server.mapper.base64;

import java.io.UnsupportedEncodingException;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import org.apache.commons.codec.binary.Base64;



/**
 * @Description Base64加密测试类
 * @Author Chongwen.jiang
 * @Date 2019/7/29 10:20
 * @ModifyDate 2019/7/29 10:20
 * @Params
 * @Return
 */
public class Base64Test {

	public static void main(String[] args) {
		final String text = "字串文字";
		try {
			final byte[] textByte = text.getBytes("UTF-8");
			//编码
			final String encodedText = Base64.encodeBase64String(textByte);
			System.out.println(encodedText);
			//解码
			System.out.println(new String(Base64.decodeBase64(encodedText), "UTF-8"));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		//解码
	}
	


}

