package me.huqiao.java.security.certificate;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.crypto.Cipher;

import me.huqiao.java.security.base64.Base64Util;

/**
 * 数字证书工具类
 * @author huqiao
 */
public class CertificateUtil {

	
	public static void main(String[] args) throws Exception{
		
		X509Certificate cer = (X509Certificate) getCertificate("D:\\test.cer");  
		
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		
		System.out.println("版本："+cer.getVersion());
		System.out.println("序列号："+Integer.toHexString(cer.getSerialNumber().intValue()));
		System.out.println("签名算法："+cer.getSigAlgName());
		System.out.println("颁发者："+cer.getIssuerDN());
		System.out.println("有限期从:" + sdf.format(cer.getNotBefore()) + "到" + sdf.format(cer.getNotAfter()));
		System.out.println("使用者：" + cer.getSubjectDN());
		
		String pwd = "123456";
		String alias = "blog.huqiao.me";
		KeyStore keyStore = getKeyStore("D:\\test.keystore", pwd);
		
		PrivateKey priKey = (PrivateKey)keyStore.getKey(alias, pwd.toCharArray());
		
		
		Certificate cer2 = keyStore.getCertificate(alias);
		PublicKey pubKey = cer2.getPublicKey();
		System.out.println("-------------Private Key-----------------");
		System.out.println(Base64Util.encode(priKey.getEncoded()));
		System.out.println("-------------Public Key-----------------");
		System.out.println(Base64Util.encode(pubKey.getEncoded()));
		
		String data = "Hello,Certificate";
		System.out.println("原文：" + data);
		
		String sign = sign(data, keyStore, alias, pwd);
		System.out.println("签名：" + sign);
		
		boolean signVerify = signVerify(data, sign,(Certificate)cer);
		System.out.println("签名验证：" + signVerify);
		
		String encryptData = encrypt(data, cer);
		System.out.println("加密后：" + encryptData);
		
		String decryptData = decrypt(encryptData, keyStore, alias, pwd);
		System.out.println("解密后：" + decryptData);
		
	}
	
	/**
	 * 获取私钥
	 * @param keyStore
	 * @param alias
	 * @param pwd
	 * @return
	 * @throws Exception
	 */
	public static PrivateKey getPrivateKey(KeyStore keyStore,String alias,String pwd)throws Exception{
		PrivateKey priKey = (PrivateKey)keyStore.getKey(alias, pwd.toCharArray());
		return priKey;
	}
	
    /**
     * 从文件读取证书文件
     * @param certificatePath
     * @return
     * @throws Exception
     */
    public static Certificate getCertificate(String certificatePath)throws Exception {  
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");  
        FileInputStream in = new FileInputStream(certificatePath);  
        Certificate certificate = certificateFactory.generateCertificate(in);  
        in.close();  
        return certificate;  
    } 
	
    /**
     * 从文件读取KeyStore文件 
     * @param keyStoreFilePath
     * @param pwd
     * @return
     * @throws Exception
     */
    public static KeyStore getKeyStore(String keyStoreFilePath,String pwd)throws Exception{
    	KeyStore keyStore = KeyStore.getInstance("jks");
    	InputStream in = new FileInputStream(keyStoreFilePath);
    	keyStore.load(in, pwd.toCharArray());
    	return keyStore;
    }
    
    /**
     * 有限期验证
     * @param cer
     * @param date
     * @return
     */
    public static boolean verifyDate(Certificate cer,Date date){
    	 X509Certificate x509Certificate = (X509Certificate) cer;  
         try {
			x509Certificate.checkValidity(date);
			return true;
		} catch (Exception e) {
			return false;
		}  
    }
    
    /**
     * 签名
     * @param data
     * @param cer
     * @return
     */
    public static String sign(String data,KeyStore keyStore,String alias,String pwd)throws Exception{
    	PrivateKey privateKey = getPrivateKey(keyStore, alias, pwd);
    	X509Certificate cer = (X509Certificate)keyStore.getCertificate(alias);
    	Signature signature = Signature.getInstance(cer.getSigAlgName());
    	signature.initSign(privateKey);
    	signature.update(data.getBytes("UTF-8"));
    	return Base64Util.encode(signature.sign());
    }
    
    /**
     * 验证签名
     * @param sign
     * @param cer
     * @return
     */
    public static boolean signVerify(String data,String sign,Certificate cer)throws Exception{
    	byte[] signData = Base64Util.decode(sign);
    	PublicKey publicKey = cer.getPublicKey();
    	Signature signature = Signature.getInstance(((X509Certificate)cer).getSigAlgName());
    	signature.initVerify(publicKey);
    	signature.update(data.getBytes());
    	return signature.verify(signData);
    }
    
    /**
     * 加密
     * @param data
     * @param cer
     * @return
     */
    public static String encrypt(String data,Certificate cer)throws Exception{
    	PublicKey publicKey = cer.getPublicKey();
    	Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
    	cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    	byte[] encrypedData = cipher.doFinal(data.getBytes("UTF-8"));
    	return Base64Util.encode(encrypedData);
    }
    
    /**
     * 解密
     * @param data
     * @param cer
     * @return
     */
    public static String decrypt(String data,KeyStore keyStore,String alias,String pwd)throws Exception{
    	PrivateKey privteKey = getPrivateKey(keyStore, alias, pwd);
    	Cipher cipher = Cipher.getInstance(privteKey.getAlgorithm());
    	cipher.init(Cipher.DECRYPT_MODE, privteKey);
    	byte[] decrypedData = cipher.doFinal(Base64Util.decode(data));
    	return new String(decrypedData,"UTF-8");
    }
    
}
