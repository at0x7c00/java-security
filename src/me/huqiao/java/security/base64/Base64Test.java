package me.huqiao.java.security.base64;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class Base64Test {
	
	public static void main(String[] args) throws Exception{
		
		BASE64Decoder decoder = new BASE64Decoder();
		BASE64Encoder encoder = new BASE64Encoder();
		
		String str = "HelloHelloHelloHelloHelloHelloHelloHelloHello";
		byte[] bytes = str.getBytes();
		String encodedStr = encoder.encodeBuffer(bytes);
		System.out.println(encodedStr);
		
		byte[] decodedBytes = decoder.decodeBuffer(encodedStr);
		System.out.println(new String(decodedBytes));
		
	}

}
