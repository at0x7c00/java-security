package me.huqiao.java.security.base64;

import java.security.MessageDigest;

import sun.misc.BASE64Encoder;

public class MD5Test {

	public static void main(String[] args) throws Exception {
		MessageDigest md = MessageDigest.getInstance("MD5");
		
		String pwd = "a";
		
		byte[] md5Bytes = md.digest(pwd.getBytes("UTF-8"));
		
		System.out.println(new String(Hex.encode(md5Bytes)));
		
		BASE64Encoder bencoder = new BASE64Encoder();
		System.out.println(bencoder.encode(md5Bytes));
		
		
		
	}
}
