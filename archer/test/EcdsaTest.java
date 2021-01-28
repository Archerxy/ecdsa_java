package archer.test;

import archer.algorithm.ecdsa.*;

public class EcdsaTest {
	public static void main(String[] args) {
		secpTest();
	}
    
    public static void secpTest() {
    	String priKeyHex = "43EFA45ABDA29F5E4A7FEFABC3DACF7ACFF4EAAF861AF5DFFF3AD1F6543F3ACA";
    	String hashStr = "FAE432CE3DDAFCE3457FEFABC3DACF7ACFF4EAAF861AF5DFFF3AFACEB56D4AA4";

    	byte[] privBytes = NumberUtil.hexStrToBytes(priKeyHex);
    	byte[] hashBytes = NumberUtil.hexStrToBytes(hashStr);

    	Ecdsa secp256k1 = Ecdsa.from(Curve.SECP_256_K1);

    	String sig = secp256k1.sign(privBytes, hashBytes);
    	System.out.println(sig);
    	

    	byte[] pubBytes = secp256k1.privateKeyToPublicKey(privBytes);
    	System.out.println(NumberUtil.bytesToHexStr(pubBytes));
		
    	System.out.println(secp256k1.verify(pubBytes, hashBytes, sig));
		
    	byte[] pubBs = secp256k1.recoverToPublicKey(hashBytes, sig);
    	System.out.println(NumberUtil.bytesToHexStr(pubBs));
    }
}
