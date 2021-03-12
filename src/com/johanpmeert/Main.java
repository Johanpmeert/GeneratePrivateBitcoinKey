package com.johanpmeert;

import org.bitcoinj.core.Base58;
import org.bitcoinj.core.ECKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.bitcoinj.core.Utils.sha256hash160;

public class Main {

    public static void main(String[] args) {
        System.out.println("Bitcoin key generator");
        System.out.println("---------------------");
        final String upperLimit = "F".repeat(56);
        byte[] random32bytes = new byte[32];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(random32bytes);
        String hexRandom = byteArrayToHexString(random32bytes);
        //
        // Test existing private key below, uncheck 5 lines below:
        /*
        String testPrivateKey = "5JimjqWwCSedgNxG6fVjX8ai3YUT34EjHT56gtK6fbxgjoR3WnP";
        if (!Base58ChecksumValid(testPrivateKey)) {
            return;
        }
        hexRandom = Base58CheckDecode(testPrivateKey).substring(2);
        */
        // Test existing SegWit Private key (or Compressed Private key) below, uncheck 7 lines below:
        /*
        String testSegwitKey = "KwaUEWZPwdUtWCoN35xRKbRvp5MRH246VEJrLQTyBmgQWSZAyDGE";
        if (!Base58ChecksumValid(testSegwitKey)) {
            return;
        }
        String rawSegWitKey = Base58CheckDecode(testSegwitKey);
        System.out.println("raw segwit: " + rawSegWitKey);
        hexRandom = rawSegWitKey.substring(2, rawSegWitKey.length() - 2);
        */
        // Test private key below, uncheck:
        /*
        hexRandom = "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D";
        if (hexRandom.length() != 64) {
            System.out.println("Not 32 random bytes, but " + hexRandom.length() / 2);
            return;
        }
        */
        System.out.println("\nSecure random 32 bytes: " + hexRandom);
        if (hexRandom.substring(0, 55).equals(upperLimit)) {
            System.out.println("Random number is out of bounds");
            return;
        } else {
            System.out.println("Random number is in valid range");
        }
        //
        // generate standard bitcoin address
        String privKey = Base58CheckEncode("80" + hexRandom);
        System.out.println("\nPrivate key (WIF): " + privKey);
        String hexPubKey = privToPublic(hexRandom);
        System.out.println("Hex public key: " + hexPubKey);
        String rawBitcoinAddress = hashShaRipemd(hexPubKey);
        System.out.println("Hex bitcoin address: " + rawBitcoinAddress);
        String bitcoinAddress = Base58CheckEncode("00" + rawBitcoinAddress);
        System.out.println("Bitcoin address: " + bitcoinAddress);
        //
        // generate compressed bitcoin address
        String privCompressedKey = Base58CheckEncode("80" + hexRandom + "01");
        System.out.println("\nCompressed Private key (WIF): " + privCompressedKey);
        String compressedPubKey = privToCompressedPublic(hexRandom);
        System.out.println("Hex compressed Public key: " + compressedPubKey);
        String rawCompressedBitcoinAddress = hashShaRipemd(compressedPubKey);
        System.out.println("Hex bitcoin address: " + rawCompressedBitcoinAddress);
        String compressedBitcoinAddres = Base58CheckEncode("00" + rawCompressedBitcoinAddress);
        System.out.println("Compressed Bitcoin address: " + compressedBitcoinAddres);
        //
        // generate Segwit address
        System.out.println("\nCompressed Private key (WIF): " + privCompressedKey);
        String hashedCompressedPubKey = rawCompressedBitcoinAddress;
        String redeemScript = "0014" + hashedCompressedPubKey;  // = OP_PUSH hashedCompressedPubKey
        System.out.println("Redeemscript: " + redeemScript);
        String hashedRedeemScript = hashShaRipemd(redeemScript);
        System.out.println("Hashed redeemscript: " + hashedRedeemScript);
        String segwitAddress = Base58CheckEncode("05" + hashedRedeemScript);
        System.out.println("Segwit address: " + segwitAddress);
    }

    public static String Base58CheckEncode(String address) {
        String base58encoded = "";
        byte[] checksum1 = hexStringToByteArray(address);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] checksum2 = digest.digest(checksum1);
            byte[] checksum3 = digest.digest(checksum2);
            String checksum4 = byteArrayToHexString(checksum3);
            address = address + checksum4.substring(0, 8);
            base58encoded = Base58.encode(hexStringToByteArray(address));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return base58encoded;
    }

    public static String Base58CheckDecode(String address) {
        String undoBase58 = byteArrayToHexString(Base58.decode(address));
        String undoChecksum = undoBase58.substring(0, undoBase58.length() - 8);
        return undoChecksum;
    }

    public static boolean Base58ChecksumValid(String address) {
        try {
            String undoBase58 = byteArrayToHexString(Base58.decode(address));
            String checkSum1 = undoBase58.substring(undoBase58.length() - 8);
            String undoChecksum = undoBase58.substring(0, undoBase58.length() - 8);
            byte[] checkSum2 = hexStringToByteArray(undoChecksum);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] checkSum3 = digest.digest(checkSum2);
            byte[] checkSum4 = digest.digest(checkSum3);
            String checkSum5 = byteArrayToHexString(checkSum4);
            String calculatedCheckSum = checkSum5.substring(0, 8);
            System.out.println("Base58 checksum validation, testing: " + address + ", base: " + undoChecksum + ", checksum: " + checkSum1 + ", Calculated checksum: " + calculatedCheckSum);
            return calculatedCheckSum.equals(checkSum1);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return false;
    }

    public static byte[] privToPublic(byte[] address) {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
        org.bouncycastle.math.ec.ECPoint pointQ = spec.getG().multiply(new BigInteger(1, address));
        byte[] publickKeyByte = pointQ.getEncoded(false);
        return publickKeyByte;
    }

    public static String privToPublic(String address) {
        return byteArrayToHexString(privToPublic(hexStringToByteArray(address)));
    }

    public static byte[] privToCompressedPublic(byte[] address) {
        ECKey key = ECKey.fromPrivate(address);
        return key.getPubKey();
    }

    public static String privToCompressedPublic(String address) {
        return byteArrayToHexString(privToCompressedPublic(hexStringToByteArray(address)));
    }

    public static byte[] hashShaRipemd(byte[] address) {
        byte[] doublehash = sha256hash160(address);
        return doublehash;
    }

    public static String hashShaRipemd(String address) {
        return byteArrayToHexString(hashShaRipemd(hexStringToByteArray(address)));
    }

    public static byte[] hexStringToByteArray(String hex) {
        hex = hex.length() % 2 != 0 ? "0" + hex : hex;
        byte[] b = new byte[hex.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(hex.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }
        return b;
    }

    public static String byteArrayToHexString(byte[] bytes) {
        final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}
