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
 * ����֤�鹤����
 * @author huqiao
 */
public class CertificateUtil {

	
	public static void main(String[] args) throws Exception{
		
		X509Certificate cer = (X509Certificate) getCertificate("D:\\test.cer");  
		
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		
		System.out.println("�汾��"+cer.getVersion());
		System.out.println("���кţ�"+Integer.toHexString(cer.getSerialNumber().intValue()));
		System.out.println("ǩ���㷨��"+cer.getSigAlgName());
		System.out.println("�䷢�ߣ�"+cer.getIssuerDN());
		System.out.println("�����ڴ�:" + sdf.format(cer.getNotBefore()) + "��" + sdf.format(cer.getNotAfter()));
		System.out.println("ʹ���ߣ�" + cer.getSubjectDN());
		
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
		System.out.println("ԭ�ģ�" + data);
		
		String sign = sign(data, keyStore, alias, pwd);
		System.out.println("ǩ����" + sign);
		
		boolean signVerify = signVerify(data, sign,(Certificate)cer);
		System.out.println("ǩ����֤��" + signVerify);
		
		String encryptData = encrypt(data, cer);
		System.out.println("���ܺ�" + encryptData);
		
		String decryptData = decrypt(encryptData, keyStore, alias, pwd);
		System.out.println("���ܺ�" + decryptData);
		
	}
	
	/**
	 * ��ȡ˽Կ
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
     * ���ļ���ȡ֤���ļ�
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
     * ���ļ���ȡKeyStore�ļ� 
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
     * ��������֤
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
     * ǩ��
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
     * ��֤ǩ��
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
     * ����
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
     * ����
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
