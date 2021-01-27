package archer.algorithm.ecdsa;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * 
 * Copyright (c) 2021 Archerxy
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * @author archer
 *
 */

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
	
    /**
	 * @param hexStr, hex number in string.
	 * 
	 * @return bytes, number in bytes.
	 * */
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

    /**
	 * @param bs, number in bytes.
	 * 
	 * @return string, hex number in string.
	 * */
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

    /**
	 * @param bs, number in bytes.
	 * 
	 * @return java.math.BigInteger.
	 * */
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

    /**
	 * @param n, java.math.BigInteger.
	 * 
	 * @return bytes, number in bytes.
	 * */
	public static byte[] bigIntToBytes(BigInteger n) {
		byte[] bs = n.toByteArray();
		if(bs[0] == 0)
			return Arrays.copyOfRange(bs, 1, bs.length);
		return bs;
	}
}
