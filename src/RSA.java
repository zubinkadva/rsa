/*
* Author: Zubin Kadva, Zongqiao Liu
* CSE 5673 Cryptology Fall 2016
* An implementation of the RSA algorithm
*/

import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static java.util.Arrays.asList;
import static java.util.Arrays.copyOfRange;

public class RSA {

    private final String KEYS = "-K", PUBLIC_KEY = "-p", SECRET_KEY = "-s", BITS = "-b",
            CERTAINTY = "-y", ENCRYPT = "-e", DECRYPT = "-d", PLAIN = "-m",
            CIPHER = "-c", FILE_ERROR = "File not found!!";
    private final boolean JDK8 = Integer.parseInt(System.getProperty("java.version").split("\\.")[1]) > 7;
    private BigInteger p, q, n, e, dp, dq, qInv, plain, cipher;
    private List<BigInteger> temp;

    public static void main(String[] args) {
        List options = asList(args);
        RSA rsa = new RSA();
        rsa.start(options);
    }

    // RSA OPS BEGIN

    private void start(List options) {
        String publicKeyFile, secretKeyFile, plainFile, cipherFile;
        try {
            if (options.contains(KEYS)) {
                if (generateKeysCheck(options)) {
                    int bits = Integer.parseInt(options.get(options.indexOf(BITS) + 1).toString());
                    int certainty = (int) Double.parseDouble(
                            options.get(options.indexOf(CERTAINTY) + 1).toString());
                    publicKeyFile = options.get(options.indexOf(PUBLIC_KEY) + 1).toString();
                    secretKeyFile = options.get(options.indexOf(SECRET_KEY) + 1).toString();
                    generateKeys(bits, certainty, publicKeyFile, secretKeyFile);
                    return;
                }
            } else if (options.contains(ENCRYPT)) {
                if (encryptCheck(options)) {
                    publicKeyFile = options.get(options.indexOf(PUBLIC_KEY) + 1).toString();
                    plainFile = options.get(options.indexOf(PLAIN) + 1).toString();
                    cipherFile = options.get(options.indexOf(CIPHER) + 1).toString();
                    encrypt(publicKeyFile, plainFile, cipherFile);
                    return;
                }
            } else if (options.contains(DECRYPT)) {
                if (decryptCheck(options)) {
                    secretKeyFile = options.get(options.indexOf(SECRET_KEY) + 1).toString();
                    plainFile = options.get(options.indexOf(PLAIN) + 1).toString();
                    cipherFile = options.get(options.indexOf(CIPHER) + 1).toString();
                    decrypt(secretKeyFile, plainFile, cipherFile);
                    return;
                }
            }
            showHelp();
        } catch (Exception e) {
            System.out.println("Error!!");
        }
    }

    private BigInteger pad(BigInteger n, BigInteger message) {
        int k = toBytes(n.bitLength()), mLen = toBytes(message.bitLength()), ps = k - mLen - 3;
        SecureRandom secureRandom = new SecureRandom();
        byte[] em = new byte[k], temp;

        // Length checking
        if (mLen > k - 11) {
            System.out.println("Message too long!!");
            return null;
        }

        // EM = 0x00 || 0x02 || PS || 0x00 || M.
        em[0] = 0x00;
        em[1] = 0x02;
        em[2 + ps] = 0x00;

        // EME-PKCS1-v1_5 encoding
        for (int i = 0; i < ps; i++) {
            temp = new byte[1];
            do {
                secureRandom.nextBytes(temp);
            } while (temp[0] == 0);
            em[2 + i] = temp[0];
        }

        System.arraycopy(message.toByteArray(), 0, em, 2 + ps + 1, mLen);
        return new BigInteger(em);
    }

    private BigInteger unpad(BigInteger n, BigInteger cipher) {
        int k = toBytes(n.bitLength()), cLen = toBytes(cipher.bitLength());
        final String DECRYPTION_ERROR = "Decryption error!!";

        // Length checking
        if (k < 11 || cLen != k - 1) {
            System.out.println(DECRYPTION_ERROR);
            return null;
        }

        // EME-PKCS1-v1_5 decoding
        byte[] val = cipher.toByteArray();
        int index = new String(val).indexOf(new String(new byte[]{0x00})) + 1;
        byte[] ps = copyOfRange(val, 1, index), message = copyOfRange(val, index, val.length);

        if (val[0] != 0x02 || index == 0 || ps.length < 8) {
            System.out.println(DECRYPTION_ERROR);
            return null;
        }

        return new BigInteger(message);
    }

    private void encrypt(String publicKeyFile, String plainFile, String cipherFile) {
        try {
            temp = readKeys(publicKeyFile);
            n = temp.get(0);
            e = temp.get(1);
            plain = pad(n, new BigInteger(read(plainFile).trim().getBytes()));
            if (plain == null) return;
            cipher = plain.modPow(e, n);        // c = m^e mod n
            System.out.println("Cipher text: " + toHex(cipher));
            //write(cipherFile, toHex(cipher));
            write(cipherFile, cipher.toByteArray());
            Files.write(Paths.get(cipherFile), cipher.toByteArray());
        } catch (Exception e) {
            System.out.println(FILE_ERROR);
        }
    }

    private void decrypt(String secretKeyFile, String plainFile, String cipherFile) {
        try {
            temp = readKeys(secretKeyFile);
            //cipher = new BigInteger(read(cipherFile).trim(), 16);
            cipher = new BigInteger(read(new File(cipherFile)));
            n = temp.get(0);
            p = temp.get(3);
            q = temp.get(4);
            dp = temp.get(5);
            dq = temp.get(6);
            qInv = temp.get(7);
            BigInteger m1 = cipher.modPow(dp, p);        // m1 = c^dp mod p
            BigInteger m2 = cipher.modPow(dq, q);       // m2 = c^dq mod q
            BigInteger h = (m1.subtract(m2)).multiply(qInv).mod(p);      // h = ((m1 - m2) * qInv) mod p
            plain = unpad(n, m2.add(q.multiply(h)));      // m = m2 + q * h
            if (plain == null) return;
            System.out.println("m1 = " + toHex(m1));
            System.out.println("m2 = " + toHex(m2));
            System.out.println("h  = " + toHex(h));
            System.out.println("Plain text: " + new String(plain.toByteArray()));
            write(plainFile, new String(plain.toByteArray()));
        } catch (Exception e) {
            System.out.println(FILE_ERROR);
        }
    }

    private void generateKeys(int bits, int certainty,
                              String publicKeyFile, String secretKeyFile) throws IOException {
        p = new BigInteger(bits, certainty, new SecureRandom());

        do
            q = new BigInteger(bits, certainty, new SecureRandom());
        while (!p.gcd(q).equals(BigInteger.valueOf(1)));

        n = p.multiply(q);      // n = p * q
        BigInteger phiN = p.subtract(BigInteger.valueOf(1)).
                multiply(q.subtract(BigInteger.valueOf(1)));        // phiN = (p - 1) * (q - 1)

        do
            e = new BigInteger(bits, new SecureRandom());
        while (!e.gcd(phiN).equals(BigInteger.valueOf(1)));

        BigInteger d = e.modInverse(phiN);      // d = e^-1 mod phiN
        dp = d.mod((p.subtract(BigInteger.valueOf(1))));        // dp = d mod (p - 1)
        dq = d.mod((q.subtract(BigInteger.valueOf(1))));        // dq = d mod (q - 1)
        qInv = q.modInverse(p);     // qInv = q^-1 mod p

        System.out.println("n    = " + toHex(n));
        System.out.println("e    = " + toHex(e));
        System.out.println("d    = " + toHex(d));
        System.out.println("p    = " + toHex(p));
        System.out.println("q    = " + toHex(q));
        System.out.println("dp   = " + toHex(dp));
        System.out.println("dq   = " + toHex(dq));
        System.out.println("qInv = " + toHex(qInv));

        writeKeys(publicKeyFile, n, e);
        writeKeys(secretKeyFile, n, e, d, p, q, dp, dq, qInv);
    }

    // RSA OPS END

    // FILE I/O FUNCTIONS BEGIN

    private String read(String name) throws IOException {
        FileReader fileReader = new FileReader(new File(name));
        BufferedReader bufferedReader = new BufferedReader(fileReader);
        String s, r = "";
        while ((s = bufferedReader.readLine()) != null)
            r += s + " ";
        bufferedReader.close();
        fileReader.close();
        return r;
    }

    private void write(String name, String data) throws IOException {
        FileWriter fileWriter = new FileWriter(new File(name));
        fileWriter.write(data);
        fileWriter.close();
    }

    private byte[] read(File file) throws IOException {
        if (JDK8) return Files.readAllBytes(Paths.get(file.toString()));
        FileInputStream fileInputStream = new FileInputStream(file);
        byte[] bFile = new byte[(int) file.length()];
        int temp = fileInputStream.read(bFile);
        fileInputStream.close();
        if (temp < 0) return new byte[]{};
        return bFile;

    }

    private void write(String file, byte[] data) throws IOException {
        if (JDK8) Files.write(Paths.get(file), data);
        else {
            FileOutputStream fileStream = new FileOutputStream(file);
            fileStream.write(data);
        }
    }

    private void writeKeys(String file, BigInteger... values) throws IOException {
        try (FileOutputStream fileStream = new FileOutputStream(file)) {
            for (BigInteger b : values) {
                if (JDK8) fileStream.write(Base64.getEncoder().encode(b.toByteArray()));
                else fileStream.write(DatatypeConverter.printBase64Binary(b.toByteArray()).getBytes());
                fileStream.write(new byte[]{(byte) '\n'});
            }
        }
    }

    private List<BigInteger> readKeys(String file) throws IOException {
        FileInputStream fileInputStream = new FileInputStream(file);
        BufferedReader br = new BufferedReader(new InputStreamReader(fileInputStream));
        List<BigInteger> list = new ArrayList<>();
        String strLine;
        while ((strLine = br.readLine()) != null) {
            if (JDK8) list.add(new BigInteger(DatatypeConverter.parseBase64Binary(strLine)));
            else list.add(new BigInteger(Base64.getDecoder().decode(strLine.getBytes())));
        }
        br.close();
        return list;
    }

    // FILE I/O FUNCTIONS END

    // VALIDATION FUNCTIONS BEGIN

    private boolean generateKeysCheck(List options) {
        return options.contains(PUBLIC_KEY) && options.contains(SECRET_KEY) &&
                options.contains(BITS) && options.contains(CERTAINTY);
    }

    private boolean encryptCheck(List options) {
        return options.contains(PLAIN) && options.contains(PUBLIC_KEY) &&
                options.contains(CIPHER);
    }

    private boolean decryptCheck(List options) {
        return options.contains(CIPHER) && options.contains(SECRET_KEY) &&
                options.contains(PLAIN);
    }

    // VALIDATION FUNCTIONS END

    // UTILITY FUNCTIONS BEGIN

    private void showHelp() {
        String help = "Usage:\njava " + RSA.class.getName() + " " + KEYS + " " + PUBLIC_KEY +
                " <public_key_file> " + SECRET_KEY + " <secret_key_file> " +
                BITS + " <bits> " + CERTAINTY + " <Miller_Rabin_certainty>\n" +
                "java " + RSA.class.getName() + " -h\n" +
                "java " + RSA.class.getName() + " " + ENCRYPT + " " + PLAIN + " " + " <plaintext_file> " +
                PUBLIC_KEY + " <public_key_file> " + CIPHER + " <ciphertext_file>\n" +
                "java " + RSA.class.getName() + " " + DECRYPT + " " + CIPHER + " " + " <ciphertext_file> " +
                SECRET_KEY + " <secret_key_file> " + PLAIN + " <plaintext_file>";
        System.out.println(help);
    }

    private static int toBytes(int bits) {
        return (int) Math.ceil(bits / 8.0);
    }

    private String toHex(BigInteger bigInteger) {
        return bigInteger.toString(16).toUpperCase();
    }

    // UTILITY FUNCTIONS END

}
