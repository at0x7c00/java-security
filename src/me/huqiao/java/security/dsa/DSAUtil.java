package me.huqiao.java.security.dsa;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import me.huqiao.java.security.base64.Base64Util;

public class DSAUtil {

	static final String ALGORITHM = "DSA";
	
	private static KeyPair getKeyPair()throws Exception{
		KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
		generator.initialize(1024);
		return generator.genKeyPair();
	}
	

	
	/**
	 * 用私钥签名
	 * @param data
	 * @param privateKey
	 * @return
	 */
	public static String sign(String data,String privateKey)throws Exception{
		PrivateKey priKey = getPrivateKey(privateKey);
		Signature sign = Signature.getInstance(ALGORITHM);
		sign.initSign(priKey);
		sign.update(data.getBytes("UTF-8"));
		byte[] signBytes = sign.sign();
		return Base64Util.encode(signBytes);
	}
	
	/**
	 * 用公钥进行签名验证
	 * @param data
	 * @param publicKey
	 * @param signData
	 * @return
	 * @throws Exception
	 */
	public static boolean verify(String data,String publicKey,String signData)throws Exception{
		PublicKey pubKey = getPublicKey(publicKey);
		Signature sign = Signature.getInstance(ALGORITHM);
		sign.initVerify(pubKey);
		sign.update(data.getBytes("UTF-8"));
		return sign.verify(Base64Util.decode(signData));
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
	
	public static void main(String[] args) throws Exception{
		String data = "Hello,DSA";
		String[] keyPair = getStringKeyPair();
		String pubKey = keyPair[0];
		String priKey = keyPair[1];
		System.out.println("原文：" + data);
		System.out.println("---------Public Key----------");
		System.out.println(pubKey);
		System.out.println("---------Private Key----------");
		System.out.println(priKey);
		System.out.println();
		
		String signData = sign(data, priKey);
		System.out.println("Sign Data:" + signData);
		System.out.println("Verify Result:" + verify(data, pubKey, signData));
		
	}
}
