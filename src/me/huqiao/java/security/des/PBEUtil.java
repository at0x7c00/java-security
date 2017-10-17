package me.huqiao.java.security.des;

import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import me.huqiao.java.security.base64.Base64Util;

public class PBEUtil {

	static final String ALGORITHM = "PBEWITHMD5andDES";
	
	private static SecretKey parseKeyFromString(String key) throws Exception{
		PBEKeySpec pbeKey = new PBEKeySpec(key.toCharArray());
		SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
		return factory.generateSecret(pbeKey);
	}
	
	/**
	 * PBE 加密
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static String encrypt(String data,String key,byte[] salt)throws Exception{
		SecretKey secretKey = parseKeyFromString(key);
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		PBEParameterSpec params = new PBEParameterSpec(salt, 100);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey,params);
		byte[] bytes = cipher.doFinal(data.getBytes("UTF-8"));
		return Base64Util.encode(bytes);
	}
	
	/**
	 * DES 解密
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static String decrypt(String data,String key,byte[] salt)throws Exception{
		SecretKey secretKey = parseKeyFromString(key);
		Cipher cipher = Cipher.getInstance(ALGORITHM); 
		PBEParameterSpec params = new PBEParameterSpec(salt, 100);
		cipher.init(Cipher.DECRYPT_MODE, secretKey,params);
		byte[] bytes = cipher.doFinal(Base64Util.decode(data));
		return new String(bytes,"UTF-8");
	}
	
	public static void main(String[] args)throws Exception {
		String str = "Hello,PBE";
		String key = "abc";
		byte[] salt = new byte[8];
		new Random().nextBytes(salt);
		System.out.println("原文：" + str);
		System.out.println("密钥：" + key);
		String encryptedStr = encrypt(str, key,salt);
		System.out.println("加密后:" + encryptedStr);
		String decryptedStr = decrypt(encryptedStr, key,salt);
		System.out.println("解密后：" + decryptedStr);
	}
	
}
