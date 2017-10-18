package me.huqiao.java.security.ecc;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import me.huqiao.java.security.base64.Base64Util;

public class ECCUtil {
	
	static final String ALGORITHM = "EC";
	
	private static KeyPair getKeyPair()throws Exception{
		KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
		generator.initialize(571);
		return generator.genKeyPair();
	}
	
	private static PublicKey getPublicKey(String key)throws Exception{
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64Util.decode(key));
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		PublicKey k = keyFactory.generatePublic(keySpec);
		return k;
	}
	
	private static PrivateKey getPrivateKey(String key)throws Exception{
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64Util.decode(key));
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		PrivateKey k = keyFactory.generatePrivate(keySpec);
		return k;
	}
	
	/**
	 * 获取字符串类型的密钥对
	 * @return
	 * @throws Exception
	 */
	public static String[] getStringKeyPair()throws Exception{
		KeyPair keyPair = getKeyPair();
		return keyPairToStringArray(keyPair);
	}
	
	private static String[] keyPairToStringArray(KeyPair keyPair){
		String[] res = new String[2];
		PublicKey pubKey = keyPair.getPublic(); 
		PrivateKey priKey = keyPair.getPrivate();
		
		res[0] = Base64Util.encode(pubKey.getEncoded());
		res[1] = Base64Util.encode(priKey.getEncoded());
		
		return res;
	}
	
	/**
	 * 加密
	 * @param data
	 * @param privateKey
	 * @return
	 */
	public static String encrypt(String data,String privateKey)throws Exception{
		PrivateKey priKey = getPrivateKey(privateKey);
		Cipher cipher = Cipher.getInstance(ALGORITHM,"SunEC");
		cipher.init(Cipher.ENCRYPT_MODE, priKey);
		byte[] bytes = cipher.doFinal(data.getBytes("UTF-8"));
		return Base64Util.encode(bytes);
	}
	
	/**
	 * 解密
	 * @param data
	 * @param publicKey
	 * @return
	 */
	public static String decrypt(String data,String publicKey)throws Exception{
		PublicKey pubKey = getPublicKey(publicKey);
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, pubKey);
		byte[] bytes = cipher.doFinal(Base64Util.decode(data));
		return new String(bytes,"UTF-8");
	}

	public static void main(String[] args) throws Exception{
		String data = "Hello,ECC";
		String[] keyPair = getStringKeyPair();
		String pubKey = keyPair[0];
		String priKey = keyPair[1];
		System.out.println("原文：" + data);
		System.out.println("---------Public Key----------");
		System.out.println(pubKey);
		System.out.println("---------Private Key----------");
		System.out.println(priKey);
		System.out.println();
		
		String signData = encrypt(data, priKey);
		System.out.println("加密后:" + signData);
		System.out.println("解密后:" + decrypt(data, pubKey));
		
		
	}
}
