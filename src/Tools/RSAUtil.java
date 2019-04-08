package Tools;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

public class RSAUtil {

	private static final String PUBLIC_KEY = "RSAPublicKey";
	private static final String PRIVATE_KEY = "RSAPrivateKey";

	/**
	 * 生成RSA的公钥和私钥
	 */
	public static Map<String, Object> initKey(){
		KeyPairGenerator keyPairGenerator = null;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		keyPairGenerator.initialize(2048);  //密钥长度
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		Map<String, Object> keyMap = new HashMap<String, Object>();
		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);
		
		return keyMap;
	}
	
	/**
	 * 获得公钥
	 */
	public static String getPublicKey(Map<String, Object> keyMap){
		RSAPublicKey publicKey = (RSAPublicKey) keyMap.get(PUBLIC_KEY);
		return Base64Util.base64Encrypt(publicKey.getEncoded());
	}
	
	public static String getKey(String path) {
		File file = new File(path);
		try (FileReader fr = new FileReader(file);
			 BufferedReader br = new BufferedReader(fr)) {
			StringBuilder sb = new StringBuilder();
			String line = null;
			while((line=br.readLine()) != null) {
				if (line.charAt(0) == '-') {
					continue;
				}
				sb.append(line+"\r\n");
			}
			sb.delete(sb.length()-2, sb.length());
			return sb.toString();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static String getKey(File file) {
		StringBuilder sb = new StringBuilder();
		
		try (FileReader fr = new FileReader(file);
			 BufferedReader br = new BufferedReader(fr)) {
			String line = null;
			while ((line = br.readLine()) != null) {
				if (line.charAt(0) == '-') {
					continue;
				}
				sb.append(line + "\r\n");
			}
			sb.delete(sb.length() - 2, sb.length());
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return sb.toString();
	}
	
	public static RSAPublicKey getpublicKey(Map<String, Object> keyMap){
		RSAPublicKey publicKey = (RSAPublicKey) keyMap.get(PUBLIC_KEY);
		return publicKey;
	}
	
	/**
	 * 获得私钥
	 */
	public static String getPrivateKey(Map<String, Object> keyMap){
		RSAPrivateKey privateKey = (RSAPrivateKey) keyMap.get(PRIVATE_KEY);
		return Base64Util.base64Encrypt(privateKey.getEncoded());
	}
	
	public static RSAPrivateKey getprivateKey(Map<String, Object> keyMap){
		RSAPrivateKey privateKey = (RSAPrivateKey) keyMap.get(PRIVATE_KEY);
		return privateKey;
	}
	
	/**
	 * 公钥加密
	 */
	public static String encrypt(String plain, String publicKey) {
		RSAPublicKey rsaPublicKey = null;
		String cipher = null;
		
		byte[] buffer = Base64Util.base64Decrypt(publicKey);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
//		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
		KeyFactory keyFactory = null;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
			rsaPublicKey = (RSAPublicKey)keyFactory.generatePublic(keySpec);
			
			Cipher c = Cipher.getInstance("RSA");
			c.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
			byte[] cipherBytes = c.doFinal(plain.getBytes());
			
			cipher = Base64Util.base64Encrypt(cipherBytes);
//			cipher = Tools.Bytes2Hex(cipherBytes);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return cipher;
	}
	
	/**
	 * 私钥解密
	 */
	public static String decrypt(String cipher, String privateKey) {
		RSAPrivateKey rsaPrivateKey = null;
		String plain = "";
		
		byte[] buffer = Base64Util.base64Decrypt(privateKey);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
		KeyFactory keyFactory = null;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
			rsaPrivateKey = (RSAPrivateKey)keyFactory.generatePrivate(keySpec);
			
			Cipher c = Cipher.getInstance("RSA");
			c.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
//			byte[] plainBytes = c.doFinal(Tools.Hex2Bytes(cipher));
			byte[] plainBytes = c.doFinal(Base64Util.base64Decrypt(cipher));
			
			plain = new String(plainBytes);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return plain;
	}
	
	/**
	 * RSA签名
	 * @param content 需要签名的内容
	 * @param privateKey 私钥
	 * @return 签名，若有错误则返回null
	 */
	public static String sign(String content, String privateKey) {
		byte[] buffer = Base64Util.base64Decrypt(privateKey);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
		
		KeyFactory keyFactory = null;
		RSAPrivateKey rsaPrivateKey = null;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
			rsaPrivateKey = (RSAPrivateKey)keyFactory.generatePrivate(keySpec);
			
			Signature signature = Signature.getInstance("SHA256WithRSA");
			signature.initSign(rsaPrivateKey);
			signature.update(content.getBytes());
			byte[] sign = signature.sign();
			
			return Base64Util.base64Encrypt(sign);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return null;
	}
	
	/**
	 * RSA签名验证
	 * @param content 内容
	 * @param sign 签名
	 * @param publicKey 公钥
	 * @return 
	 */
	public static boolean checkSign(String content, String sign, String publicKey) {
		byte[] buffer = Base64Util.base64Decrypt(publicKey);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
		
		KeyFactory keyFactory = null;
		RSAPublicKey rsaPublicKey = null;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
			rsaPublicKey = (RSAPublicKey)keyFactory.generatePublic(keySpec);
			
			Signature signature = Signature.getInstance("SHA256WithRSA");
			signature.initVerify(rsaPublicKey);
			signature.update(content.getBytes());
			
			return signature.verify(Base64Util.base64Decrypt(sign));
		} catch (Exception e) {
			return false;
		}
	}
	
	/**
	 * 公钥加密
	 */
	public static byte[] encrypt(byte[] data, RSAPublicKey publicKey) throws Exception{
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] cipherBytes = cipher.doFinal(data);
		return cipherBytes;
	}
	
	/**
	 * 私钥解密
	 */
	public static byte[] decrypt(byte[] data, RSAPrivateKey privateKey) throws Exception{
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] plainBytes = cipher.doFinal(data);
		return plainBytes;
	}
	
	public static void main(String args[]) {
		try {
			System.out.println(((PublicKey)(initKey().get(PUBLIC_KEY))));
		} catch (Exception e) {
			// TODO 自动生成的 catch 块
			e.printStackTrace();
		}
	}
}
