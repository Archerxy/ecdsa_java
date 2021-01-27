package archer.algorithm.ecdsa;

import java.math.BigInteger;
import java.util.Arrays;

public class NumberUtil {
	public static final byte DEFAULT_BYTE = 0x7f;
	
	public static final int[] hexToByteTable = new int[128];
	
	public static final char[] byteToHexTable = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };
	    
    static {
    	for(int i = 0; i < hexToByteTable.length; ++i)
    		hexToByteTable[i] = DEFAULT_BYTE; 
    	for(int i = 0; i < byteToHexTable.length; ++i)
    		hexToByteTable[byteToHexTable[i]] = i;
    }
	
	public static byte[] hexStrToBytes(String hexStr) {
		if(null == hexStr || hexStr.isEmpty())
			return new byte[0];
		String hex = hexStr.toLowerCase();
		if (hex.startsWith("0x"))
			hex = hex.substring(2);
		if(hex.length()%2 == 1)
			hex = "0"+hex;
		byte[] out = new byte[hex.length()>>1];
		for(int i = 0; i < hex.length(); i += 2) {
			char c1 = hex.charAt(i), c2 = hex.charAt(i+1);
			if(c1 < 0 || c1 > 128 || c2 < 0 || c2 > 128 || hexToByteTable[c1] == DEFAULT_BYTE || hexToByteTable[c2] == DEFAULT_BYTE)
				throw new java.lang.RuntimeException("Invalid hex string, "+hexStr);
			out[i>>1] = (byte) ((hexToByteTable[c1]<<4)|hexToByteTable[c2]);
		}
		return out;
	}
	
	public static String bytesToHexStr(byte[] bs) {
		if(null == bs || bs.length == 0)
			return "";
		StringBuilder sb = new StringBuilder();
		for(byte b: bs) {
			int bi = b;
			if(bi < 0)
				bi = 256+bi;
			int b1 = (bi>>4), b2 = bi&0b1111;
			sb.append(byteToHexTable[b1]);
			sb.append(byteToHexTable[b2]);
		}
		return sb.toString();
	}
	
	public static BigInteger bytesToBigInt(byte[] bs) {
		if(null == bs || bs.length == 0)
			return BigInteger.ZERO;
		BigInteger num = BigInteger.ZERO;
		for(byte b: bs) {
			int n = b;
			if(n < 0)
				n += 256;
			num = num.shiftLeft(8).add(BigInteger.valueOf(n));
		}
		return num;
	}
	
	public static byte[] bigIntToBytes(BigInteger n) {
		byte[] bs = n.toByteArray();
		if(bs[0] == 0)
			return Arrays.copyOfRange(bs, 1, bs.length);
		return bs;
	}
}
