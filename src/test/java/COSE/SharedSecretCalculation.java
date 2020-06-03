package COSE;

import java.math.BigInteger;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.math.Field;
import net.i2p.crypto.eddsa.math.FieldElement;
import net.i2p.crypto.eddsa.math.bigint.BigIntegerFieldElement;
import net.i2p.crypto.eddsa.math.bigint.BigIntegerLittleEndianEncoding;
import net.i2p.crypto.eddsa.math.ed25519.Ed25519FieldElement;

public class SharedSecretCalculation {

	/*
	 * Useful links:
	 * https://crypto.stackexchange.com/questions/63732/curve-25519-x25519-
	 * ed25519-convert-coordinates-between-montgomery-curve-and-t/63734
	 * 
	 * https://tools.ietf.org/html/rfc7748
	 * 
	 * https://tools.ietf.org/html/rfc8032
	 */

	// Create the ed25519 field
	private static Field ed25519Field = new Field(256, // b
			Utils.hexToBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // q(2^255-19)
			new BigIntegerLittleEndianEncoding());

	// Value of sqrt(-486664) hardcoded (note that there are 2 roots)
	private static BigIntegerFieldElement root = new BigIntegerFieldElement(ed25519Field,
			new BigInteger("51042569399160536130206135233146329284152202253034631822681833788666877215207"));

	public static void main(String args[]) throws Exception {
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 0);


		// Define test values x and y from RFC7748. Created as field elements to
		// use for calculations in the field.
		BigIntegerFieldElement x = new BigIntegerFieldElement(ed25519Field,
				new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202"));
		BigIntegerFieldElement y = new BigIntegerFieldElement(ed25519Field,
				new BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960"));

		// Define correctly calculated values of u and v from RFC7748
		BigIntegerFieldElement u_correct = new BigIntegerFieldElement(ed25519Field, new BigInteger("9"));
		BigIntegerFieldElement v_correct = new BigIntegerFieldElement(ed25519Field,
				new BigInteger("14781619447589544791020593568409986887264606134616475288964881837755586237401"));

		// Calculate u and v values
		FieldElement u = calcCurve25519_u(y);
		FieldElement v = calcCurve25519_v(x, u);

		// // Print calculated values
		// System.out.println("x: " + x);
		// System.out.println("y: " + y);
		//
		// System.out.println("v: " + v);
		// System.out.println("u: " + u);
		//
		// // Check that calculated u and v values are correct
		// if (Arrays.equals(u.toByteArray(), u_correct.toByteArray())) {
		// System.out.println("u value is correct!");
		// } else {
		// System.out.println("u value is INCORRECT!");
		// }
		// if (Arrays.equals(v.toByteArray(), v_correct.toByteArray())) {
		// System.out.println("v value is correct!");
		// } else {
		// System.out.println("v value is INCORRECT!");
		// }
		//
		// /**/
		// System.out.println();
		// System.out.println();
		// /**/
		//
		// // Testing starting with a COSE Key
		//
		// OneKey myKey = OneKey.generateKey(AlgorithmID.EDDSA);
		// FieldElement y_fromKeyAlt = extractCOSE_y_alt(myKey);
		// FieldElement y_fromKey = extractCOSE_y(myKey);
		//
		// System.out.println("y from COSE key (alt): " + y_fromKeyAlt);
		// System.out.println("y from COSE key: " + y_fromKey);
		// System.out.println("COSE key X param_: " + myKey.get(KeyKeys.OKP_X));
		//
		// System.out.println("y from COSE key (alt) (bytes): " +
		// Utils.bytesToHex(y_fromKeyAlt.toByteArray()));
		// System.out.println("y from COSE key (bytes): " +
		// Utils.bytesToHex(y_fromKey.toByteArray()));
		//
		// // Check that calculating y in both ways give the same result
		// if (Arrays.equals(y_fromKeyAlt.toByteArray(),
		// y_fromKey.toByteArray())) {
		// System.out.println("y from key value is correct!");
		// } else {
		// System.out.println("y from key value is INCORRECT!");
		// }
		//
		// /**/
		// System.out.println();
		// System.out.println();
		// /**/
		//
		// FieldElement x_fromKey = extractCOSE_x(myKey);
		// System.out.println("x from COSE key: " + x_fromKey);
		//
		// FieldElement uuu1 = calcCurve25519_u(y_fromKeyAlt);
		// FieldElement uuu2 = calcCurve25519_u(y_fromKey);
		// // calcCurve25519_v(x_fromKey, uuu1);
		// // calcCurve25519_v(x_fromKey, uuu2);

		/* -- Test decodeLittleEndian -- */

		// Input value:
		// a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4
		byte[] input = new byte[] { (byte) 0xa5, (byte) 0x46, (byte) 0xe3, (byte) 0x6b, (byte) 0xf0, (byte) 0x52,
				(byte) 0x7c, (byte) 0x9d, (byte) 0x3b, (byte) 0x16, (byte) 0x15, (byte) 0x4b, (byte) 0x82, (byte) 0x46,
				(byte) 0x5e, (byte) 0xdd, (byte) 0x62, (byte) 0x14, (byte) 0x4c, (byte) 0x0a, (byte) 0xc1, (byte) 0xfc,
				(byte) 0x5a, (byte) 0x18, (byte) 0x50, (byte) 0x6a, (byte) 0x22, (byte) 0x44, (byte) 0xba, (byte) 0x44,
				(byte) 0x9a, (byte) 0xc4 };

		// Output value (from Python code)
		// 88925887110773138616681052956207043583107764937498542285260013040410376226469
		BigInteger correct = new BigInteger(
				"88925887110773138616681052956207043583107764937498542285260013040410376226469");

		BigInteger res = decodeLittleEndian(input, 255);

		System.out.println("Expected: " + correct);
		System.out.println("Actual: " + res);
		System.out.println("Same: " + correct.equals(res));

		// --

		// Input value:
		// e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493
		input = new byte[] { (byte) 0xe5, (byte) 0x21, (byte) 0x0f, (byte) 0x12, (byte) 0x78, (byte) 0x68, (byte) 0x11,
				(byte) 0xd3, (byte) 0xf4, (byte) 0xb7, (byte) 0x95, (byte) 0x9d, (byte) 0x05, (byte) 0x38, (byte) 0xae,
				(byte) 0x2c, (byte) 0x31, (byte) 0xdb, (byte) 0xe7, (byte) 0x10, (byte) 0x6f, (byte) 0xc0, (byte) 0x3c,
				(byte) 0x3e, (byte) 0xfc, (byte) 0x4c, (byte) 0xd5, (byte) 0x49, (byte) 0xc7, (byte) 0x15, (byte) 0xa4,
				(byte) 0x93 };

		// Output value (from Python code)
		// 66779901969842027605876251890954603246052331132842480964984187926304357556709
		correct = new BigInteger(
				"66779901969842027605876251890954603246052331132842480964984187926304357556709");

		res = decodeLittleEndian(input, 255);

		System.out.println("Expected: " + correct);
		System.out.println("Actual: " + res);
		System.out.println("Same: " + correct.equals(res));

		/* -- Test decodeScalar -- */

		// Input value:
		// 3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3
		input = new byte[] { (byte) 0x3d, (byte) 0x26, (byte) 0x2f, (byte) 0xdd, (byte) 0xf9, (byte) 0xec, (byte) 0x8e,
				(byte) 0x88, (byte) 0x49, (byte) 0x52, (byte) 0x66, (byte) 0xfe, (byte) 0xa1, (byte) 0x9a, (byte) 0x34,
				(byte) 0xd2, (byte) 0x88, (byte) 0x82, (byte) 0xac, (byte) 0xef, (byte) 0x04, (byte) 0x51, (byte) 0x04,
				(byte) 0xd0, (byte) 0xd1, (byte) 0xaa, (byte) 0xe1, (byte) 0x21, (byte) 0x70, (byte) 0x0a, (byte) 0x77,
				(byte) 0x9c, (byte) 0x98, (byte) 0x4c, (byte) 0x24, (byte) 0xf8, (byte) 0xcd, (byte) 0xd7, (byte) 0x8f,
				(byte) 0xbf, (byte) 0xf4, (byte) 0x49, (byte) 0x43, (byte) 0xeb, (byte) 0xa3, (byte) 0x68, (byte) 0xf5,
				(byte) 0x4b, (byte) 0x29, (byte) 0x25, (byte) 0x9a, (byte) 0x4f, (byte) 0x1c, (byte) 0x60, (byte) 0x0a,
				(byte) 0xd3 };

		// Output value (from Python code)
		// 41823108910914769844969816812214719139234914957831430028237854386113666295352
		correct = new BigInteger("41823108910914769844969816812214719139234914957831430028237854386113666295352");

		res = decodeScalar(input);

		System.out.println("Expected: " + correct);
		System.out.println("Actual: " + res);
		System.out.println("Same: " + correct.equals(res));

		// --

		// Input value:
		// 4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d
		input = new byte[] { (byte) 0x4b, (byte) 0x66, (byte) 0xe9, (byte) 0xd4, (byte) 0xd1, (byte) 0xb4, (byte) 0x67,
				(byte) 0x3c, (byte) 0x5a, (byte) 0xd2, (byte) 0x26, (byte) 0x91, (byte) 0x95, (byte) 0x7d, (byte) 0x6a,
				(byte) 0xf5, (byte) 0xc1, (byte) 0x1b, (byte) 0x64, (byte) 0x21, (byte) 0xe0, (byte) 0xea, (byte) 0x01,
				(byte) 0xd4, (byte) 0x2c, (byte) 0xa4, (byte) 0x16, (byte) 0x9e, (byte) 0x79, (byte) 0x18, (byte) 0xba,
				(byte) 0x0d };

		// Output value (from Python code)
		// 35156891815674817266734212754503633747128614016119564763269015315466259359304
		correct = new BigInteger("35156891815674817266734212754503633747128614016119564763269015315466259359304");

		res = decodeScalar(input);

		System.out.println("Expected: " + correct);
		System.out.println("Actual: " + res);
		System.out.println("Same: " + correct.equals(res));

		/* -- Test decodeUCoordinate -- */

		// Input value:
		// e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493
		input = new byte[] { (byte) 0xe5, (byte) 0x21, (byte) 0x0f, (byte) 0x12, (byte) 0x78, (byte) 0x68, (byte) 0x11,
				(byte) 0xd3, (byte) 0xf4, (byte) 0xb7, (byte) 0x95, (byte) 0x9d, (byte) 0x05, (byte) 0x38, (byte) 0xae,
				(byte) 0x2c, (byte) 0x31, (byte) 0xdb, (byte) 0xe7, (byte) 0x10, (byte) 0x6f, (byte) 0xc0, (byte) 0x3c,
				(byte) 0x3e, (byte) 0xfc, (byte) 0x4c, (byte) 0xd5, (byte) 0x49, (byte) 0xc7, (byte) 0x15, (byte) 0xa4,
				(byte) 0x93 };

		// Output value (from Python code)
		// 8883857351183929894090759386610649319417338800022198945255395922347792736741
		correct = new BigInteger("8883857351183929894090759386610649319417338800022198945255395922347792736741");

		res = decodeUCoordinate(input);

		System.out.println("Expected: " + correct);
		System.out.println("Actual: " + res);
		System.out.println("Same: " + correct.equals(res));

		// --

		// Input value:
		// 06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086
		input = new byte[] { (byte) 0x06, (byte) 0xfc, (byte) 0xe6, (byte) 0x40, (byte) 0xfa, (byte) 0x34, (byte) 0x87,
				(byte) 0xbf, (byte) 0xda, (byte) 0x5f, (byte) 0x6c, (byte) 0xf2, (byte) 0xd5, (byte) 0x26, (byte) 0x3f,
				(byte) 0x8a, (byte) 0xad, (byte) 0x88, (byte) 0x33, (byte) 0x4c, (byte) 0xbd, (byte) 0x07, (byte) 0x43,
				(byte) 0x7f, (byte) 0x02, (byte) 0x0f, (byte) 0x08, (byte) 0xf9, (byte) 0x81, (byte) 0x4d, (byte) 0xc0,
				(byte) 0x31, (byte) 0xdd, (byte) 0xbd, (byte) 0xc3, (byte) 0x8c, (byte) 0x19, (byte) 0xc6, (byte) 0xda,
				(byte) 0x25, (byte) 0x83, (byte) 0xfa, (byte) 0x54, (byte) 0x29, (byte) 0xdb, (byte) 0x94, (byte) 0xad,
				(byte) 0xa1, (byte) 0x8a, (byte) 0xa7, (byte) 0xa7, (byte) 0xfb, (byte) 0x4e, (byte) 0xf8, (byte) 0xa0,
				(byte) 0x86 };

		// Output value (from Python code)
		// 22503099155545401511747743372988183427981498984445290765916415810160808098822
		correct = new BigInteger("22503099155545401511747743372988183427981498984445290765916415810160808098822");

		res = decodeUCoordinate(input);

		System.out.println("Expected: " + correct);
		System.out.println("Actual: " + res);
		System.out.println("Same: " + correct.equals(res));

		/* -- Test encodeUCoordinate -- */

		// Input value:
		// 8883857351183929894090759386610649319417338800022198945255395922347792736741
		BigInteger inputInt = new BigInteger(
				"8883857351183929894090759386610649319417338800022198945255395922347792736741");

		// Output value (from Python code)
		// e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a413
		byte[] correctArray = new byte[] { (byte) 0xe5, (byte) 0x21, (byte) 0x0f, (byte) 0x12, (byte) 0x78, (byte) 0x68,
				(byte) 0x11, (byte) 0xd3, (byte) 0xf4, (byte) 0xb7, (byte) 0x95, (byte) 0x9d, (byte) 0x05, (byte) 0x38,
				(byte) 0xae, (byte) 0x2c, (byte) 0x31, (byte) 0xdb, (byte) 0xe7, (byte) 0x10, (byte) 0x6f, (byte) 0xc0,
				(byte) 0x3c, (byte) 0x3e, (byte) 0xfc, (byte) 0x4c, (byte) 0xd5, (byte) 0x49, (byte) 0xc7, (byte) 0x15,
				(byte) 0xa4, (byte) 0x13 };

		byte[] resArray = encodeUCoordinate(inputInt);

		System.out.println("Expected: " + Utils.bytesToHex(correctArray));
		System.out.println("Actual: " + Utils.bytesToHex(resArray));
		System.out.println("Same: " + Arrays.equals(correctArray, resArray));

		// --

		// Input value:
		// 5834050823475987305959238492374969056969794868074987349740858586932482375934
		inputInt = new BigInteger("5834050823475987305959238492374969056969794868074987349740858586932482375934");

		// Output value (from Python code)
		// e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a413
		correctArray = new byte[] { (byte) 0xfe, (byte) 0x80, (byte) 0x97, (byte) 0x47, (byte) 0xf0, (byte) 0x4e,
				(byte) 0x46, (byte) 0xf8, (byte) 0x35, (byte) 0xaa, (byte) 0x79, (byte) 0x60, (byte) 0xdc, (byte) 0x0d,
				(byte) 0xa8, (byte) 0x52, (byte) 0x1d, (byte) 0x4a, (byte) 0x68, (byte) 0x14, (byte) 0xd9, (byte) 0x0a,
				(byte) 0xca, (byte) 0x92, (byte) 0x5f, (byte) 0xa0, (byte) 0x85, (byte) 0xfa, (byte) 0xab, (byte) 0xf4,
				(byte) 0xe5, (byte) 0x0c };

		resArray = encodeUCoordinate(inputInt);

		System.out.println("Expected: " + Utils.bytesToHex(correctArray));
		System.out.println("Actual: " + Utils.bytesToHex(resArray));
		System.out.println("Same: " + Arrays.equals(correctArray, resArray));

		// Input value:
		// 5834050823475987305959238492374969056969794868074987349740858586932482375934
		inputInt = new BigInteger("5834050823475987305959238492374969056969794868074987349740858586932482375934");

		// Output value (from Python code)
		// e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a413
		correctArray = new byte[] { (byte) 0xfe, (byte) 0x80, (byte) 0x97, (byte) 0x47, (byte) 0xf0, (byte) 0x4e,
				(byte) 0x46, (byte) 0xf8, (byte) 0x35, (byte) 0xaa, (byte) 0x79, (byte) 0x60, (byte) 0xdc, (byte) 0x0d,
				(byte) 0xa8, (byte) 0x52, (byte) 0x1d, (byte) 0x4a, (byte) 0x68, (byte) 0x14, (byte) 0xd9, (byte) 0x0a,
				(byte) 0xca, (byte) 0x92, (byte) 0x5f, (byte) 0xa0, (byte) 0x85, (byte) 0xfa, (byte) 0xab, (byte) 0xf4,
				(byte) 0xe5, (byte) 0x0c };

		resArray = encodeUCoordinate(inputInt);

		System.out.println("Expected: " + Utils.bytesToHex(correctArray));
		System.out.println("Actual: " + Utils.bytesToHex(resArray));
		System.out.println("Same: " + Arrays.equals(correctArray, resArray));

		/* Test cswap */

		// First no swap

		BigInteger a_bi = new BigInteger(
				"8883857351183929894090759386610649319417338800022198945255395922347792736741");
		BigInteger b_bi = new BigInteger(
				"5834050823475987305959238492374969056969794868074987349740858586932482375934");

		BigIntegerFieldElement a = new BigIntegerFieldElement(ed25519Field, a_bi);
		BigIntegerFieldElement b = new BigIntegerFieldElement(ed25519Field, b_bi);

		BigInteger swap = BigInteger.ZERO;

		Tuple result = cswap(swap, a, b);
		System.out.println("Swap correct: " + result.a.equals(a) + " and " + result.b.equals(b));

		// Now do swap

		swap = BigInteger.ONE;
		result = cswap(swap, a, b);
		System.out.println("Swap correct: " + result.a.equals(b) + " and " + result.b.equals(a));

		/* Test X25519 */
		
		byte[] k0 = new byte[] { (byte) 0xa5, (byte) 0x46, (byte) 0xe3, (byte) 0x6b, (byte) 0xf0, (byte) 0x52,
				(byte) 0x7c, (byte) 0x9d, (byte) 0x3b, (byte) 0x16, (byte) 0x15, (byte) 0x4b, (byte) 0x82, (byte) 0x46,
				(byte) 0x5e, (byte) 0xdd, (byte) 0x62, (byte) 0x14, (byte) 0x4c, (byte) 0x0a, (byte) 0xc1, (byte) 0xfc,
				(byte) 0x5a, (byte) 0x18, (byte) 0x50, (byte) 0x6a, (byte) 0x22, (byte) 0x44, (byte) 0xba, (byte) 0x44,
				(byte) 0x9a, (byte) 0xc4 };
		byte[] u0 = new byte[] { (byte) 0xe6, (byte) 0xdb, (byte) 0x68, (byte) 0x67, (byte) 0x58, (byte) 0x30,
				(byte) 0x30, (byte) 0xdb, (byte) 0x35, (byte) 0x94, (byte) 0xc1, (byte) 0xa4, (byte) 0x24, (byte) 0xb1,
				(byte) 0x5f, (byte) 0x7c, (byte) 0x72, (byte) 0x66, (byte) 0x24, (byte) 0xec, (byte) 0x26, (byte) 0xb3,
				(byte) 0x35, (byte) 0x3b, (byte) 0x10, (byte) 0xa9, (byte) 0x03, (byte) 0xa6, (byte) 0xd0, (byte) 0xab,
				(byte) 0x1c, (byte) 0x4c };
		byte[] r0 = new byte[] { (byte) 0xc3, (byte) 0xda, (byte) 0x55, (byte) 0x37, (byte) 0x9d, (byte) 0xe9,
				(byte) 0xc6, (byte) 0x90, (byte) 0x8e, (byte) 0x94, (byte) 0xea, (byte) 0x4d, (byte) 0xf2, (byte) 0x8d,
				(byte) 0x08, (byte) 0x4f, (byte) 0x32, (byte) 0xec, (byte) 0xcf, (byte) 0x03, (byte) 0x49, (byte) 0x1c,
				(byte) 0x71, (byte) 0xf7, (byte) 0x54, (byte) 0xb4, (byte) 0x07, (byte) 0x55, (byte) 0x77, (byte) 0xa2,
				(byte) 0x85, (byte) 0x52 };

		byte[] rp = X25519(k0, u0);
		
		System.out.println("RP: " + Utils.bytesToHex(rp));

		// X25519(u, v);
	}

	private static byte[] X25519(byte[] k, byte[] u) {

		BigInteger kn = decodeScalar(k);
		BigInteger un = decodeUCoordinate(u);

		BigIntegerFieldElement kn_bif = new BigIntegerFieldElement(ed25519Field, kn);
		BigIntegerFieldElement un_bif = new BigIntegerFieldElement(ed25519Field, un);

		FieldElement res = X25519_calculate(kn_bif, un_bif);

		BigInteger res_bi = new BigInteger(invertArray(res.toByteArray()));

		return encodeUCoordinate(res_bi);

	}

	/**
	 * Implements the XX25519 function.
	 * 
	 * See https://tools.ietf.org/html/rfc7748#section-5
	 */
	private static FieldElement X25519_calculate(FieldElement k, FieldElement u) {

		// Set bits
		// https://tools.ietf.org/html/rfc7748#page-7
		int bits = 255;

		// Initialize starting values
		FieldElement x_1 = u;
		FieldElement x_2 = new BigIntegerFieldElement(ed25519Field, new BigInteger("1"));
		
		FieldElement z_2 = new BigIntegerFieldElement(ed25519Field, new BigInteger("0"));
		
		FieldElement x_3 = u;
		FieldElement z_3 = new BigIntegerFieldElement(ed25519Field, new BigInteger("1"));
		
		BigInteger swap = new BigInteger("0");
		
		// https://tools.ietf.org/html/rfc7748#page-8
		FieldElement a24 = new BigIntegerFieldElement(ed25519Field, new BigInteger("121665"));

		// Uninitialized variables used in loop

		FieldElement A;
		FieldElement AA;
		FieldElement B;
		FieldElement BB;
		FieldElement E;
		FieldElement C;
		FieldElement D;
		FieldElement DA;
		FieldElement CB;

		// For loop here
		for (int t = bits - 1; t >= 0; t--) {

			// Swap step

			BigInteger k_bi = new BigInteger(invertArray(k.toByteArray()));
			// k_t = (k >> t) & 1
			BigInteger k_t = (k_bi.shiftRight(t)).and(BigInteger.ONE);

			swap = swap.xor(k_t); // swap ^= k_t

			// Swapping
			Tuple result = cswap(swap, x_2, x_3);
			x_2 = result.a;
			x_3 = result.b;
			// End swapping

			// Swapping
			Tuple result2 = cswap(swap, z_2, z_3);
			z_2 = result2.a;
			z_3 = result2.b;
			// End swapping

			swap = k_t; // swap = k_t

			// Calculation step

			A = x_2.add(z_2); // A = x_2 + z_2

			AA = A.multiply(A); // AA = A^2

			B = x_2.subtract(z_2); // B = x_2 - z_2

			BB = B.multiply(B); // B = B^2

			E = AA.subtract(BB); // E = AA - BB

			C = x_3.add(z_3); // C = x_3 + z_3

			D = x_3.subtract(z_3); // D = x_3 - z_3

			DA = D.multiply(A); // DA = D * A

			CB = C.multiply(B); // CB = C * B

			FieldElement DA_a_CB = DA.add(CB);
			x_3 = DA_a_CB.multiply(DA_a_CB); // x_3 = (DA + CB)^2

			FieldElement DA_s_CB = DA.subtract(CB);
			FieldElement DA_s_CB__x__DA_s_CB = DA_s_CB.multiply(DA_s_CB);
			z_3 = x_1.multiply(DA_s_CB__x__DA_s_CB); // z_3 = x_1 * (DA - CB)^2

			x_2 = AA.multiply(BB); // x_2 = AA * BB

			FieldElement a24_x_E = a24.multiply(E);
			FieldElement AA__a__a24_x_E = AA.add(a24_x_E);
			z_2 = E.multiply(AA__a__a24_x_E); // z_2 = E * (AA + a24 * E)
		}

		// Final swap step
		
		// Swapping
		Tuple result = cswap(swap, x_2, x_3);
		x_2 = result.a;
		x_3 = result.b;
		// End swapping

		// Swapping
		Tuple result2 = cswap(swap, z_2, z_3);
		z_2 = result2.a;
		z_3 = result2.b;
		// End swapping

		// Return step

		// Calculate p
		BigInteger pow = new BigInteger("2").pow(255);
		BigInteger p_bi = pow.subtract(new BigInteger("19"));
		FieldElement p = new BigIntegerFieldElement(ed25519Field, p_bi);

		// Calculate p minus 2
		FieldElement p_s_2 = p.subtractOne().subtractOne();

		// Calculate z_2^(p - 2)
		BigInteger z_2_bi = new BigInteger(invertArray(z_2.toByteArray()));
		BigIntegerFieldElement z_2_bif = new BigIntegerFieldElement(ed25519Field, z_2_bi);
		FieldElement val = z_2_bif.pow(p_s_2);

		// Calculate return vale
		FieldElement ret = x_2.multiply(val);

		return ret;

	}

	private static BigInteger decodeLittleEndian(byte[] b, int bits) {

		byte[] cutArray = Arrays.copyOf(b, (bits + 7) / 8);

		BigInteger res = new BigInteger(1, invertArray(cutArray));

		return res;
		
	}

	private static BigInteger decodeScalar(byte[] b) {

		b[0] &= 248;
		b[31] &= 127;
		b[31] |= 64;

		return decodeLittleEndian(b, 255);

	}

	private static BigInteger decodeUCoordinate(byte[] u) {

		int bits = 255;

		for (int i = 0; i < u.length; i++) {
			if ((u[i] % 8) != 0) {
				u[u.length - 1] &= (1 << (bits % 8)) - 1;
			}
		}

		return decodeLittleEndian(u, bits);
	}

	// TODO: Optimize
	private static byte[] encodeUCoordinate(BigInteger u) {

		int bits = 255;

		BigInteger pow = new BigInteger("2").pow(255);
		BigInteger p_bi = pow.subtract(new BigInteger("19"));

		u = u.mod(p_bi); // u = u % p
		
		byte[] res = new byte[(bits + 7) / 8];

		for (int i = 0; i < ((bits + 7) / 8); i++) {
			BigInteger temp = u.shiftRight(8 * i);
			byte[] temp2 = temp.toByteArray();
			// System.out.println((byte) (temp2[temp2.length - 1]));

			res[i] = temp2[temp2.length - 1];
		}

		return res;
	}

	static class Tuple {

		public FieldElement a;
		public FieldElement b;

		Tuple(FieldElement a, FieldElement b) {

			BigInteger a_bi = new BigInteger(invertArray(a.toByteArray()));
			BigInteger b_bi = new BigInteger(invertArray(b.toByteArray()));

			this.a = new BigIntegerFieldElement(ed25519Field, a_bi);
			this.b = new BigIntegerFieldElement(ed25519Field, b_bi);
		}

	}

	// TODO: Make constant time
	private static Tuple cswap(BigInteger swap, FieldElement a, FieldElement b) {

		if (swap.equals(BigInteger.ONE)) {
			return new Tuple(b, a);
		} else {
			return new Tuple(a, b);
		}

	}

	///////////////////////////


	/**
	 * Calculate Curve25519 u coordinate from Ed25519 y coordinate
	 * 
	 * @param y the Ed25519 y coordinate
	 * @return the Curve25519 u coordinate
	 */
	private static FieldElement calcCurve25519_u(FieldElement y) {

		/* Calculate u from y */
		// u = (1+y)/(1-y)

		// 1 + y -> y + 1
		FieldElement one_plus_y = y.addOne();

		// 1 - y -> -y + 1
		FieldElement one_minus_y = (y.negate()).addOne();

		// invert(1 - y)
		FieldElement one_minus_y_invert = one_minus_y.invert();

		// (1 + y) / (1 - y) -> (1 + y) * invert(1 - y)
		FieldElement u = one_plus_y.multiply(one_minus_y_invert);

		return u;

	}

	/**
	 * Calculate Curve25519 v coordinate from Ed25519 x coordinate and
	 * Curve25519 u coordinate
	 * 
	 * @param x the Ed25519 x coordinate
	 * @param u the Curve25519 u coordinate
	 * @return the Curve25519 v coordinate
	 */
	private static FieldElement calcCurve25519_v(FieldElement x, FieldElement u) {

		/* Calculate v from u and x */
		// v = sqrt(-486664)*u/x

		// invert(x)
		FieldElement x_invert = x.invert();

		// u / x -> u * invert(x)
		FieldElement u_over_x = u.multiply(x_invert);

		// calculate v
		FieldElement v = root.multiply(u_over_x);

		return v;

	}

	/* COSE related functions below */

	/**
	 * Extract the y point coordinate from a COSE Key (OneKey). Alternative way
	 * using division.
	 * 
	 * @param key the COSE key
	 * @return the y point coordinate
	 * 
	 * @throws CoseException if retrieving public key part fails
	 */
	private static FieldElement extractCOSE_y_alt(OneKey key) throws CoseException {
		EdDSAPublicKey pubKey = (EdDSAPublicKey) key.AsPublicKey();

		// Get projective coordinates for Y and Z
		FieldElement Y = pubKey.getA().getY();
		FieldElement Z = pubKey.getA().getZ();

		// y = Y/Z -> y = Y * invert(Z)
		FieldElement recip = Z.invert();
		FieldElement y = Y.multiply(recip);

		return y;
	}

	/**
	 * Extract the y point coordinate from a COSE Key (OneKey). Way using the X
	 * value of the key directly, clearing one bit.
	 * https://tools.ietf.org/html/rfc8032#section-5.1.2
	 * 
	 * @param key the COSE key
	 * @return the y point coordinate
	 * 
	 * @throws CoseException if retrieving public key part fails
	 */
	private static FieldElement extractCOSE_y(OneKey key) throws CoseException {

		// Retrieve X value from COSE key as byte array
		byte[] X_value = key.get(KeyKeys.OKP_X).GetByteString();

		// Clear most significant bit of the final octet in the X value (that
		// indicates sign of x coordinate). The result is the y coordinate.
		byte[] y_array = X_value.clone();
		y_array[y_array.length - 1] &= 0B01111111;

		// The array must be reversed to have correct byte order
		// BigInteger wants Big Endian but it is in Little Endian
		byte[] y_array_inv = invertArray(y_array);
		
		// Create field element for y from updated X value
		FieldElement y = new BigIntegerFieldElement(ed25519Field, new BigInteger(y_array_inv));

		return y;
	}

	/**
	 * Extract the x point coordinate from a COSE Key (OneKey). Way using
	 * division.
	 * 
	 * @param key the COSE key
	 * @return the x point coordinate
	 * 
	 * @throws CoseException if retrieving public key part fails
	 */
	private static FieldElement extractCOSE_x(OneKey key) throws CoseException {
		EdDSAPublicKey pubKey = (EdDSAPublicKey) key.AsPublicKey();

		// Get projective coordinates for X and Z
		FieldElement X = pubKey.getA().getX();
		FieldElement Z = pubKey.getA().getZ();

		// x = X/Z -> x = X * invert(Z)
		FieldElement recip = Z.invert();
		FieldElement x = X.multiply(recip);

		return x;
	}

	/**
	 * Invert a byte array
	 * 
	 * @param input the input byte array
	 * @return the inverted byte array
	 */
	private static byte[] invertArray(byte[] input) {
		byte[] output = input.clone();
		for (int i = 0; i < input.length; i++) {
			output[i] = input[input.length - i - 1];
		}
		return output;
	}
}
