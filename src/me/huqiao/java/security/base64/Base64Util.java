package me.huqiao.java.security.base64;

import java.io.IOException;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class Base64Util {
	
	public static void main(String[] args) throws Exception{
		String str = "Hello";
		byte[] bytes = str.getBytes();
		String encodedStr = encode(bytes);
		System.out.println(encodedStr);
		
		byte[] decodedBytes = decode(encodedStr);
		System.out.println(new String(decodedBytes));
		
	}
	
	public static String encode(byte[] bytes){
		return new BASE64Encoder().encode(bytes);
	}
	
	public static byte[] decode(String encodeStr) throws IOException{
		return new BASE64Decoder().decodeBuffer(encodeStr);
	}

}
