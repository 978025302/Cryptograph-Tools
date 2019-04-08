package Tools;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;

public class Tools {
	private final static String CAURL = "http://192.168.43.53/verify.php";
	
	public static String Bytes2Hex(byte[] bytes) {
		StringBuilder builder = new StringBuilder();

		for (int i = 0; i < bytes.length; i++) {
			if (Integer.toHexString(0xFF & bytes[i]).length() == 1)
				builder.append("0").append(Integer.toHexString(0xFF & bytes[i]));
			else
				builder.append(Integer.toHexString(0xFF & bytes[i]));
		}

		return builder.toString();
	}

	public static byte[] Hex2Bytes(String hex) {
		byte[] bytes = new byte[hex.length() / 2];

		for (int i = 0; i < hex.length() / 2; i++) {
			String subStr = hex.substring(i * 2, i * 2 + 2);
			bytes[i] = (byte) Integer.parseInt(subStr, 16);
		}

		return bytes;
	}

	public static String ASCII2Hex(String str) {
		char[] chars = str.toCharArray();

		StringBuffer hex = new StringBuffer();
		for (int i = 0; i < chars.length; i++) {
			hex.append(Integer.toHexString((int) chars[i]));
		}

		return hex.toString();
	}

	public static String Hex2ASCII(String hex) {
		StringBuilder sb = new StringBuilder();
		StringBuilder temp = new StringBuilder();

		for (int i = 0; i < hex.length() - 1; i += 2) {

			// grab the hex in pairs
			String output = hex.substring(i, (i + 2));
			// convert hex to decimal
			int decimal = Integer.parseInt(output, 16);
			// convert the decimal to character
			sb.append((char) decimal);

			temp.append(decimal);
		}

		return sb.toString();
	}

	/**
	 * 根据公钥、私钥和明文构造数字信封，并且用RSA私钥签名
	 * 
	 * @param plain         需要加密的明文
	 * @param AES_key       AES私钥
	 * @param RSA_PublicKey 对方的RSA公钥
	 * @return 加密后的数字信封，其中用","隔开头部和密文
	 */
	public static String EncEnvelope(String plain, String AES_key, String RSA_PublicKey) {
		String head = RSAUtil.encrypt(AES_key, RSA_PublicKey);
		final String RSA_PrivateKey = RSAUtil.getKey("key/rsa_private_key_bank.pem");
		String cipher = AESUtil.encryptAES(plain, AES_key);
		String content = head + "," + cipher;
		String sign = RSAUtil.sign(content, RSA_PrivateKey);
		return content + ";" + sign + ";client";
	}

	/**
	 * 解密电子信封
	 * 
	 * @param envelope       需要解密的信封
	 * @param RSA_PrivateKey RSA私钥
	 * @return 解密后的AES_密钥以及明文，String[0]为密钥，String[1]为明文
	 */
	public static String[] DecEnvelope(String envelope, String RSA_PrivateKey) {
		String[] info = envelope.split(",");
		String[] result = new String[2];
		String AES_Key = RSAUtil.decrypt(info[0], RSA_PrivateKey);
		String plain = AESUtil.decryptAES(info[1], AES_Key);
		result[0] = AES_Key;
		result[1] = plain;
		return result;
	}
	
	/**
	 * 解析出证书中的公钥
	 * @param DC 证书
	 * @return 如果证书有效则返回公钥，反之返回null
	 */
	public static String checkDC(String DC) {
		String[] info = DC.split("\r\n|\n|\r");
		if (info.length != 3) return null;
		
		if (RSAUtil.checkSign(info[1], info[2], RSAUtil.getKey("key/CApublickey.pem"))) {
			String CAreply = sendPost(CAURL, "institute=" + info[0] + "&code=apiroot&submit=搜索");
			if (CAreply.charAt(CAreply.length()-2) == '3') {
				return info[1];
			}
//			return info[1];
		}
		return null;
	}
	
	public static String URLEncode(String str) {
		String result = null;
		try {//用url编码，防止+改成空格
			result = URLEncoder.encode(str, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		
		return result;
	}
	
	/**
	 * 将付款码发送给某个url
	 * 返回web的回复
	 */
	public static String sendPost(String url, String param) {
		PrintWriter out = null;
		BufferedReader in = null;
		StringBuilder reply = new StringBuilder();
		try {
			URL realUrl = new URL(url);
			// 打开和URL之间的连接
			URLConnection conn = realUrl.openConnection();
			// 设置通用的请求属性
			conn.setRequestProperty("accept", "*/*");
			conn.setRequestProperty("connection", "Keep-Alive");
			conn.setRequestProperty("user-agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;SV1)");
			// 发送POST请求必须设置如下两行
			conn.setDoOutput(true);
			conn.setDoInput(true);
			conn.setReadTimeout(2000);
			conn.setConnectTimeout(2000);
			// 获取URLConnection对象对应的输出流
			out = new PrintWriter(conn.getOutputStream());
			// 发送请求参数
			out.print(param);
			// flush输出流的缓冲
			out.flush();
			// 定义BufferedReader输入流来读取URL的响应
			in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			String line;
			while ((line = in.readLine()) != null) {
				reply.append(line);
			}
		} catch (SocketTimeoutException ste) {
			return "time out";
		} catch (Exception e) {
			System.out.println("发送 POST 请求出现异常！" + e);
			e.printStackTrace();
		}

		return reply.toString();
	}
}
