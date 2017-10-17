package me.huqiao.java.security.md5;

import java.security.MessageDigest;

import me.huqiao.java.security.base64.Base64Util;
import me.huqiao.java.security.base64.Hex;

public class MD5Util {

	public static void main(String[] args) throws Exception {
		MessageDigest md = MessageDigest.getInstance("MD5");
		String pwd = "a";
		
		byte[] md5Bytes = md.digest(pwd.getBytes("UTF-8"));
		System.out.println(new String(Hex.encode(md5Bytes)));
		System.out.println(Base64Util.encode(md5Bytes));
		
		
	}
}
