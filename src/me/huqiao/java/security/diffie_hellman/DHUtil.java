package me.huqiao.java.security.diffie_hellman;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import me.huqiao.java.security.base64.Base64Util;

public class DHUtil {
	
	public final static String ALGORITHM = "DH";
	public final static String SYMMETRIC_SECRET_ALGORITHM = "AES";//对称加密算法名称

	/**
	 * 产生密钥对
	 * @return
	 * @throws Exception
	 */
	public static KeyPair getKeyPair()throws Exception{
		KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
		generator.initialize(1024);
		return generator.generateKeyPair();
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
	
	public static String[] getStringKeyPair(String publicKey)throws Exception{
		KeyPair keyPair = getKeyPairByPublicKey(publicKey);
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
	 * 由一个公钥产生密钥对
	 * @param publicKey
	 * @return
	 * @throws Exception
	 */
	public static KeyPair getKeyPairByPublicKey(String publicKey)throws Exception{
		
		PublicKey pKey = getPublicKey(publicKey);
		
		KeyPairGenerator generator = KeyPairGenerator.getInstance(pKey.getAlgorithm());
		
		DHParameterSpec dhGenParam = ((DHPublicKey) pKey).getParams();
		generator.initialize(dhGenParam);
		
		return generator.generateKeyPair();
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
	 * 根据一方公钥和另外一方私钥构建本地密钥
	 * @param publicKey
	 * @param privateKey
	 * @return
	 * @throws Exception
	 */
	public static SecretKey getAgreementSecretKey(String publicKey,String privateKey)throws Exception{
		PublicKey pubKey = getPublicKey(publicKey);
		PrivateKey priKey = getPrivateKey(privateKey);
		
		return getAgreementSecretKey(pubKey,priKey);
		
	}
	
	public static SecretKey getAgreementSecretKey(PublicKey pubKey,PrivateKey priKey)throws Exception{
		KeyAgreement argeement = KeyAgreement.getInstance(pubKey.getAlgorithm());
		argeement.init(priKey);
		argeement.doPhase(pubKey, true);
		
		SecretKey secretKey = argeement.generateSecret(SYMMETRIC_SECRET_ALGORITHM);
		return secretKey;
	}
	
	/**
	 * 加密
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static String encrypt(String data,SecretKey key)throws Exception{
		Cipher cipher = Cipher.getInstance(key.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encryptedData = cipher.doFinal(data.getBytes("UTF-8"));
		return Base64Util.encode(encryptedData);
	}
	
	/**
	 * 解密
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static String decrypt(String data,SecretKey key)throws Exception{
		byte[] encryptedData = Base64Util.decode(data);
		Cipher cipher = Cipher.getInstance(key.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] decryptedData = cipher.doFinal(encryptedData);
		return new String(decryptedData,"UTF-8");
	}
	
	public static void main(String[] args) throws Exception {
		KeyPair keyPair = getKeyPair();
		PublicKey aPublicKey = keyPair.getPublic();
		PrivateKey aPrivateKey = keyPair.getPrivate();
		
		KeyPair bKeyPair = getKeyPairByPublicKey(keyPairToStringArray(keyPair)[0]);
		
		PublicKey bPublicKey = bKeyPair.getPublic();
		PrivateKey bPrivateKey = bKeyPair.getPrivate();
		
		String data = "Hello";
		System.out.println("原文：" + data);
		System.out.println("--------------b to a------------------");
		SecretKey key = getAgreementSecretKey(aPublicKey, bPrivateKey);
		String encrypedData = encrypt(data, key);
		System.out.println("加密后:"+encrypedData);
		
		SecretKey key2 = getAgreementSecretKey(bPublicKey,aPrivateKey);
		String decrypedData = decrypt(encrypedData, key2);
		System.out.println("解密后："+decrypedData);
		
		System.out.println("--------------a to b------------------");
		key = getAgreementSecretKey(bPublicKey, aPrivateKey);
		encrypedData = encrypt(data, key);
		System.out.println("加密后:"+encrypedData);
		
		key2 = getAgreementSecretKey(aPublicKey,bPrivateKey);
		decrypedData = decrypt(encrypedData, key2);
		System.out.println("解密后："+decrypedData);
		
	}
	
}
