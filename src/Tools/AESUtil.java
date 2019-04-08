package Tools;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES算法编程实现
 * @author xzb
 *
 */
public class AESUtil {
	
	private static SecureRandom random = new SecureRandom();

	/**
	 * 生成密钥
	 * @throws Exception 
	 */
	public static byte[] initKey() {
		KeyGenerator keyGen = null;
		//密钥生成器
		try {
			keyGen = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		//初始化密钥生成器
		keyGen.init(256);  //默认128，获得无政策权限后可用192或256
		//生成密钥
		SecretKey secretKey = keyGen.generateKey();
		return secretKey.getEncoded();
	}
	
	/**
	 * 生成指定长度的密钥
	 * @param keyLength 密钥的长度，可选128/192/256
	 * @return 生成后的密钥
	 */
	public static String initKey(int keyLength) {
		KeyGenerator keyGen = null;
		try {
			keyGen = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		//初始化密钥生成器
		keyGen.init(keyLength);  //默认128，获得无政策权限后可用192或256
		//生成密钥
		SecretKey secretKey = keyGen.generateKey();
		
		return Tools.Bytes2Hex(secretKey.getEncoded());
	}
	
	/**
	 * 加密
	 * @throws Exception 
	 */
	public static String encryptAES(String plain, String key){
		byte[] iv = random.generateSeed(16);
		
		byte[] encrypt = null;
		//恢复密钥
		SecretKey secretKey = new SecretKeySpec(key.getBytes(), "AES");
		try {
			//Cipher完成加密
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			//根据密钥对cipher进行初始化
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
			//加密
			encrypt = cipher.doFinal(plain.getBytes());
		} catch (Exception e) {
			e.printStackTrace();
		}
		byte[] result = new byte[encrypt.length+16];
		System.arraycopy(iv, 0, result, 0, 16);
		System.arraycopy(encrypt, 0, result, 16, encrypt.length);
		return Base64Util.base64Encrypt(result);
	}
	
	/**
	 * 加密
	 * @throws Exception 
	 */
	public static byte[] encryptAES(byte[] plain, byte[] key) throws Exception{
		//恢复密钥
		SecretKey secretKey = new SecretKeySpec(key, "AES");
		//Cipher完成加密
		Cipher cipher = Cipher.getInstance("AES");
		//根据密钥对cipher进行初始化
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		//加密
		byte[] encrypt = cipher.doFinal(plain);
		
		return encrypt;
	}
	
	/**
	 * 解密
	 */
	public static String decryptAES(String ciper, String key) {
		byte[] buffer = Base64Util.base64Decrypt(ciper);
		byte[] iv = new byte[16];
		byte[] cipherBytes = new byte[buffer.length-16];
		byte[] test = new byte[16];
		System.arraycopy(buffer, 0, iv, 0, 16);
		System.arraycopy(buffer, 16, cipherBytes, 0, buffer.length-16);
		System.arraycopy(buffer, buffer.length-16, test, 0, 16);
		
		byte[] plain = null;
		//恢复密钥生成器
		SecretKey secretKey = new SecretKeySpec(key.getBytes(), "AES");
		//Cipher完成解密
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			//根据密钥对cipher进行初始化
			cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
			plain = cipher.doFinal(cipherBytes);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return new String(plain);
	}
//	public static String decryptAES(String ciper, String key) {
//		byte[] plain = null;
//		//恢复密钥生成器
//		SecretKey secretKey = new SecretKeySpec(key.getBytes(), "AES");
//		//Cipher完成解密
//		try {
//			Cipher cipher = Cipher.getInstance("AES");
//			//根据密钥对cipher进行初始化
//			cipher.init(Cipher.DECRYPT_MODE, secretKey);
//			plain = cipher.doFinal(Base64Util.base64Decrypt(ciper));
//		} catch (Exception e) {
//			e.printStackTrace();
//		}
//		return new String(plain);
//	}
	
	/**
	 * 解密
	 */
	public static byte[] decryptAES(byte[] ciper, byte[] key) throws Exception{
		//恢复密钥生成器
		SecretKey secretKey = new SecretKeySpec(key, "AES");
		//Cipher完成解密
		Cipher cipher = Cipher.getInstance("AES");
		//根据密钥对cipher进行初始化
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		byte[] plain = cipher.doFinal(ciper);
		return plain;
	}
}
