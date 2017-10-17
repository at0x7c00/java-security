package me.huqiao.java.security.hmac;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import me.huqiao.java.security.base64.Base64Util;

public class HMACUtil {

	public static void main(String[] args) throws Exception {
		
		String data = "Hello";
		String key = getKey();
		System.out.println("key:" + key);
		
		String mac = encryptHmac(key.getBytes(), data.getBytes());
		System.out.println(mac);
		
		System.out.println(encryptHmac(key.getBytes(), "Hello2".getBytes()));
		
	}
	
	public static String getKey()throws Exception{
		KeyGenerator generator = KeyGenerator.getInstance("HmacMD5");
		SecretKey key = generator.generateKey();
		byte[] bytes = key.getEncoded();
		return Base64Util.encode(bytes);
	}
	
	public static String encryptHmac(byte[] key,byte[] data)throws Exception{
		SecretKey secretKey = new SecretKeySpec(key, "HmacMD5");
		Mac mac = Mac.getInstance("HmacMD5");
		mac.init(secretKey);
		
		byte[] resultBytes = mac.doFinal(data);
	    String resultString = Base64Util.encode(resultBytes);
	    return resultString;
	}
}
