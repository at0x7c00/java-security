package me.huqiao.java.security.diffie_hellman;

import javax.crypto.SecretKey;

/**
 * ���ݴ�������
 * @author huqiao
 */
public class Server {

	private String publicKey;
	private String privateKey;
	private SecretKey key;
	
	public Server(){
		try {
			String[] keyPair = DHUtil.getStringKeyPair();
			publicKey = keyPair[0];
			privateKey = keyPair[1];
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
	
	public String service(String data,String clientPublicKey){
		System.out.println("----------------Data received at Server:----------------\r\n"+ data);
		System.out.println("----------------Client PublicKey received at Server:----------------\r\n"+clientPublicKey);
		try {
			key = DHUtil.getAgreementSecretKey(clientPublicKey, privateKey);
			String decryptedData = DHUtil.decrypt(data, key);
			System.out.println("Data decryped:" + decryptedData);
			if(verfiy(decryptedData)){
				return "OK";
			}else{
				return "Error";
				
			}
		} catch (Exception e) {
			e.printStackTrace();
			return e.getMessage();
		}
	}
	
	private boolean verfiy(String decryptedData) {
		//�����û��������룬������֤
		return true;
	}

	/**
	 * �����õ�����˹�Կ
	 * @return
	 */
	public String getPublicKey(){
		return publicKey;
	}
}
