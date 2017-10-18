package me.huqiao.java.security.rsa;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import me.huqiao.java.security.base64.Base64Util;

import com.sun.org.apache.xml.internal.security.utils.Base64;

public class RSAUtil {
	
	public final static String ALGORITHM = "RSA";
	public final static String SIGNATURE_ALGORITHM = "MD5withRSA";

	/**
	 * ��ȡ��Կ��Կ��
	 * @return
	 * @throws Exception
	 */
	public static KeyPair getKey() throws Exception{
		KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
		return generator.generateKeyPair();
	}
	
	private static Key getPublicKey(String key)throws Exception{
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64Util.decode(key));
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		Key k = keyFactory.generatePublic(keySpec);
		return k;
	}
	
	private static Key getPrivateKey(String key)throws Exception{
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64Util.decode(key));
		KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
		Key k = keyFactory.generatePrivate(keySpec);
		return k;
	}
	
	/**
	 * ʹ�ù�Կ���м���
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static String encryptByPublicKey(String data,String key)throws Exception{
		
		Key k = getPublicKey(key);
		
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, k);
		
		byte[] bytes = cipher.doFinal(data.getBytes("UTF-8"));
		
		return Base64Util.encode(bytes);
	}
	
	/**
	 * ʹ��˽Կ���м���
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static String encryptByPrivateKey(String data,String key)throws Exception{
		
		Key k = getPrivateKey(key);
		
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, k);
		
		byte[] bytes = cipher.doFinal(data.getBytes("UTF-8"));
		
		return Base64Util.encode(bytes);
	}
	
	/**
	 * ʹ����Կ���н���
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static String decryptByPrivateKey(String data,String key)throws Exception{
		Key k = getPrivateKey(key);
		
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, k);
		
		byte[] bytes = cipher.doFinal(Base64Util.decode(data));
		
		return new String(bytes,"UTF-8");
	}
	
	/**
	 * ʹ�ù�Կ���н���
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static String decryptByPublicKey(String data,String key)throws Exception{
		Key k = getPublicKey(key);
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, k);
		
		byte[] bytes = cipher.doFinal(Base64Util.decode(data));
		
		return new String(bytes,"UTF-8");
	}
	
	/**
	 * ʹ��˽Կ����ǩ��
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static String sign(String data,String key)throws Exception{
		PrivateKey k = (PrivateKey)getPrivateKey(key);
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);  
        signature.initSign(k);  
        signature.update(data.getBytes("UTF-8"));  
        return Base64.encode(signature.sign());
	}
	
	/**
	 * ʹ�ù�Կ����ǩ����֤
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static boolean signVerify(String data,String key,String sign)throws Exception{
		PublicKey k = (PublicKey)getPublicKey(key);
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);  
        signature.initVerify(k);  
        signature.update(data.getBytes("UTF-8"));
        return signature.verify(Base64.decode(sign));  
	}
	
	public static void main(String[] args) throws Exception{
		KeyPair keyPair = getKey();
		RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();
		RSAPublicKey  publicKey = (RSAPublicKey)keyPair.getPublic();
		
		String privateKeyStr = Base64.encode(privateKey.getEncoded());
		String publicKeyStr = Base64.encode(publicKey.getEncoded());
		
		System.out.println("˽Կ��" + privateKeyStr);
		System.out.println("��Կ��" + publicKeyStr);
		
		String data = "Hello,RSA,Hello,RSAHello,RSAHello,RSAHello,RSAHello,RSAHello,RSA";
		System.out.println("---------------��Կ���ܣ�˽Կ����-----------------");
		String encryptedData = encryptByPublicKey(data,publicKeyStr);
		System.out.println("���ܺ�" + encryptedData);
		
		String decryptedData = decryptByPrivateKey(encryptedData, privateKeyStr);
		System.out.println("���ܺ�" + decryptedData);
		System.out.println("---------------˽Կ���ܣ���Կ����-----------------");
		
		encryptedData = encryptByPrivateKey(data,privateKeyStr);
		System.out.println("���ܺ�" + encryptedData);
		decryptedData = decryptByPublicKey(encryptedData, publicKeyStr);
		System.out.println("���ܺ�" + decryptedData);
		
		String sign = sign(data,privateKeyStr);
		System.out.println("ǩ����" + sign);
		System.out.println("ǩ����֤��" + signVerify(data,publicKeyStr,sign));
		
		
	}
	
}
