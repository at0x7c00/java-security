package me.huqiao.java.security.des;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import me.huqiao.java.security.base64.Base64Util;

public class DESUtil {

	static final String ALGORITHM = "DES";
	
	/**
	 * �����ı���ʽ��DES Key
	 * @return
	 * @throws Exception
	 */
	public static String getKey() throws Exception{
		KeyGenerator generator = KeyGenerator.getInstance(ALGORITHM);
		generator.init(new SecureRandom());//���� 
		return Base64Util.encode(generator.generateKey().getEncoded());
	}
	
	/**
	 * ���ı� ��ʽDES Keyת����SecretKey����
	 * @param key
	 * @return
	 */
	public static SecretKey parseKeyFromString(String key)throws Exception{
		DESKeySpec desKeySpec = new DESKeySpec(Base64Util.decode(key));
		SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
		SecretKey secretKey = factory.generateSecret(desKeySpec);
		return secretKey;
	}
	
	/**
	 * DES ����
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static String encrypt(String data,String key)throws Exception{
		SecretKey secretKey = parseKeyFromString(key);
		Cipher cipher = Cipher.getInstance(ALGORITHM); 
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		byte[] bytes = cipher.doFinal(data.getBytes("UTF-8"));
		return Base64Util.encode(bytes);
	}
	
	/**
	 * DES ����
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static String decrypt(String data,String key)throws Exception{
		SecretKey secretKey = parseKeyFromString(key);
		Cipher cipher = Cipher.getInstance(ALGORITHM); 
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		byte[] bytes = cipher.doFinal(Base64Util.decode(data));
		return new String(bytes,"UTF-8");
	}
	
	public static void main(String[] args)throws Exception {
		String str = "Hello,DES";
		String key = getKey();
		System.out.println("ԭ�ģ�" + str);
		System.out.println("��Կ��" + key);
		String encryptedStr = encrypt(str, key);
		System.out.println("���ܺ�:" + encryptedStr);
		String decryptedStr = decrypt(encryptedStr, key);
		System.out.println("���ܺ�" + decryptedStr);
	}
	
}
