package me.huqiao.java.security.sha;

import java.security.MessageDigest;

import me.huqiao.java.security.base64.Base64Util;

public class SHAUtil {
	public static void main(String[] args) throws Exception{
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		String str = "Hello";
		String str2 = Base64Util.encode(md.digest(str.getBytes()));
		System.out.println(str2);
	}
}
