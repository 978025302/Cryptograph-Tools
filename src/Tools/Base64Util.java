package Tools;

import java.io.IOException;

import Decoder.BASE64Decoder;
import Decoder.BASE64Encoder;

/**
 * BASE64算法实现加解密
 * @author xzb
 *
 */
public class Base64Util {

	/**
	 * base64算法加密
	 * @param data
	 * @return
	 */
	public static String base64Encrypt(byte[] data) {
		String result = new BASE64Encoder().encode(data);
		return result;
	}
	
	/**
	 * base64算法解密
	 * @param data
	 * @return
	 * @throws Exception
	 */
//	public static String base64Decrypt(String data) throws Exception{
//		byte[] resultBytes = new BASE64Decoder().decodeBuffer(data);
//		return new String(resultBytes);
//	}
	
	/**
	 * base64算法解密
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public static byte[] base64Decrypt(String data) {
		byte[] resultBytes = null;
		try {
			resultBytes = new BASE64Decoder().decodeBuffer(data);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return resultBytes;
	}
}
