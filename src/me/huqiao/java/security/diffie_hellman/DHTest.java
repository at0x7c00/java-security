package me.huqiao.java.security.diffie_hellman;

public class DHTest {
	
	public static void main(String[] args) {
		
		Server server = new Server();
		
		Client client = new Client(server);
		boolean loginSuccess = client.login("admin", "123456");
		
		System.out.println("login success:" + loginSuccess);
		
	}

}
