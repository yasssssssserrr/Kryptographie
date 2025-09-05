package Praktikum3;

import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class SSF {

    private PublicKey pubKey;
    private PrivateKey prvKey;
    private final String sender;
    private final String empfaenger;
    private final String originalFileName;
    private final String verschluesseltFileName;
    private final int bufferSize;
    private final SecretKey secretKey;

    public SSF(String sender, String empfaenger, String originalFileName, String verschluesseltFileName, int bufferSize) {
        this.sender = sender;
        this.empfaenger = empfaenger;
        this.originalFileName = originalFileName;
        this.verschluesseltFileName = verschluesseltFileName;
        this.bufferSize = bufferSize;
        try {
            // generiert geheimen AES-Schluessel
            this.secretKey = generateSecretAesKey();

        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public SSF(String sender, String empfaenger, String originalFileName, String verschluesseltFileName) {
        this(sender, empfaenger, originalFileName, verschluesseltFileName, 1024);
    }

    public static void main(String[] args) {

        if (args.length != 4) {
            System.out.println("Falsch");

        } else {
            // SSF wird initialisiert
            SSF ssf = new SSF(args[0], args[1], args[2], args[3]);

            // nimmt public und private key vom Sender und Empfänger
            String currentDir = "C:\\Users\\Yasser Ibourk\\Desktop\\ITSPraktikum2\\src\\main\\java\\Praktikum3";
            ssf.setFileKey(currentDir + "\\"+ssf.sender);
            ssf.setFileKey(currentDir + "\\"+ssf.empfaenger);

            // nimmt key signature und schreibt in versschluesselte Datei
            byte[] signatureBytes = ssf.signKey();
            byte[] secretEncryptedKey = ssf.encryptSecretKeyWithPublicKey();
            ssf.writeEncryptedFile(signatureBytes, secretEncryptedKey);
        }
    }


    // 2.a/b
    public void setFileKey(String filePath) {
        try {
            // Informationen aus Datei lesen
            DataInputStream in = new DataInputStream(new FileInputStream(filePath));
            int InhaberNameLength = in.readInt();
            byte[] InhaberName = in.readNBytes(InhaberNameLength);
            int fileKeyLength = in.readInt();
            byte[] fileKey = in.readNBytes(fileKeyLength);

            KeyFactory keyFac = KeyFactory.getInstance("RSA");
            if (filePath.endsWith(".pub")) {
                // aus dem Byte-Array koennen wir eine X.509-Schluesselspezifikation erzeugen
                X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(fileKey);

                // nun wird aus der Spezifikation wieder abgeschlossener public key erzeugt
                setPubKey(keyFac.generatePublic(x509KeySpec));
            } else {
                // aus dem Byte-Array koennen wir eine PKCS8-Schluesselspezifikation erzeugen
                PKCS8EncodedKeySpec Pkcs8KeySpec = new PKCS8EncodedKeySpec(fileKey);
                setPrvKey(keyFac.generatePrivate(Pkcs8KeySpec));
            }

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    // 2.c AES-Schluessel generieren
    private SecretKey generateSecretAesKey() throws InvalidKeyException, NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256); // Schluessellaenge als Parameter
        SecretKey sKey = kg.generateKey();
        // zeige den Algorithmus des Schluessels

        System.out.println("Schluesselalgorithmus: " + sKey.getAlgorithm());

        // zeige das Format des Schluessels
        System.out.println("Schluesselformat: " + sKey.getFormat());

        // Ergebnis
        return sKey;
    }

    // 2.d
    public byte[] signKey() {
        byte[] signature = null;
        try {
            byte[] key = secretKey.getEncoded();
            Signature rsaSignature = Signature.getInstance("SHA512withRSA");

            // zum Signieren benoetigen wir den privaten Schluessel (hier: RSA)
            rsaSignature.initSign(getPrivateKey());

            // Daten fuer die kryptographische Hashfunktion (hier: SHA-256) liefern
            rsaSignature.update(key);

            // Signaturbytes durch Verschluesselung des Hashwerts (mit privatem RSA-Schluessel) erzeugen
            signature = rsaSignature.sign();

        } catch (NoSuchAlgorithmException ex) {
            showErrorAndExit("Implementierung fuer SHA256withRSA nicht moeglich! Algorithmus nicht gefunden.", ex);
        } catch (InvalidKeyException ex) {
            showErrorAndExit("Falscher / Ungueltiger Schluessel!", ex);
        } catch (SignatureException ex) {
            showErrorAndExit("Fehler beim Signieren!", ex);
        }
        return signature;
    }

    // 2.e
    public byte[] encryptSecretKeyWithPublicKey() {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            // Initialisierung zur Verschluesselung mit automatischer Parametererzeugung
            cipher.init(Cipher.ENCRYPT_MODE, getPublicKey());

            // Zuerst wird cipher.update(secretKey.getEncoded()) aufgerufen, um einen Teil des geheimen
            // Schluessels zu verarbeiten. Das Ergebnis wird in der Variable processedData gespeichert.
            // Dann wird cipher.doFinal() aufgerufen, um den Rest der Daten zu verarbeiten,
            // die nicht mit cipher.update() verarbeitet wurden.
            // Das Ergebnis wird in der Variable processedRest gespeichert.
            byte[] processedData = cipher.update(secretKey.getEncoded());
            byte[] processedRest = new byte[0];
            try {
                processedRest = cipher.doFinal();
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                e.printStackTrace();
            }

            return concatenate(processedData, processedRest);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }

    }

    public static byte[] concatenate(byte[] ba1, byte[] ba2) {
        int len1 = ba1.length;
        int len2 = ba2.length;
        byte[] result = new byte[len1 + len2];

        // Füllt die Ergebnisse des ersten Arrays in result
        System.arraycopy(ba1, 0, result, 0, len1);

        // Füllt die Ergebnisse des zweiten Arrays in result
        System.arraycopy(ba2, 0, result, len1, len2);

        return result;
    }


    public Cipher initCipher() {
        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

            // Initialisierung zur Verschluesselung mit automatischer Parametererzeugung
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher;

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    // 2.f
    public void writeEncryptedFile(byte[] signatureBytes, byte[] secretEncryptedKey) {

        Cipher aesCipher = initCipher();

        // der oeffentliche Schluessel vom Schluesselpaar
        PublicKey pubKey = getPublicKey();

        // wir benoetigen die Bytefolge im Default-Format
        byte[] pubKeyBytes = pubKey.getEncoded();
        try {
            // eine Datei wird erzeugt und danach die Nachricht, die Signatur
            // und der oeffentliche Schluessel darin gespeichert
            DataOutputStream os = new DataOutputStream(new FileOutputStream(getEncryptedFileName()));
            os.writeInt(secretEncryptedKey.length);
            os.write(secretEncryptedKey);
            os.writeInt(signatureBytes.length);
            os.write(signatureBytes);
            os.writeInt(aesCipher.getParameters().getEncoded().length);
            os.write(aesCipher.getParameters().getEncoded());
            FileInputStream in = new FileInputStream(getPlainFileName());
            byte[] buffer = new byte[getBufferSize()];
            int len;
            while ((len = in.read(buffer, 0, buffer.length)) > 0) {
                byte[] result = aesCipher.update(buffer, 0, len);
                os.write(result); //Verschlüsselte Dateidaten schreiben
            }
            // mit doFinal abschliessen (Rest inkl. Padding ..)
            byte[] resultRest = aesCipher.doFinal();
            if (resultRest.length > 0) {
                os.write(resultRest);
            }
            os.close();

        } catch (IOException ex) {
            showErrorAndExit("Fehler beim Schreiben der signierten Nachricht.",
                    ex);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
        // Bildschirmausgabe
        System.out.println("Der Public Key wurde in folgendem Format gespeichert: " + pubKey.getFormat());
        byteArraytoHexString(pubKeyBytes);
        System.out.println();
        System.out.println("Erzeugte SHA-256/RSA-Signatur: ");
        byteArraytoHexString(signatureBytes);
    }


    /**
     * Getter und Setter
     */

    public String getSender() {
        return sender;
    }

    public String getReceiver() {
        return empfaenger;
    }

    public String getPlainFileName() {
        return originalFileName;
    }

    public String getEncryptedFileName() {
        return verschluesseltFileName;
    }

    public int getBufferSize() {
        return bufferSize;
    }

    public PublicKey getPublicKey() {
        return pubKey;
    }

    public PrivateKey getPrivateKey() {
        return prvKey;
    }

    public void setPubKey(PublicKey pubKey) {
        this.pubKey = pubKey;
    }

    public void setPrvKey(PrivateKey prvKey) {
        this.prvKey = prvKey;
    }


    /**
     * Hilfsmethoden
     */

    private void byteArraytoHexString(byte[] byteArray) {
        for (byte b : byteArray) {
            System.out.print(bytetoHexString(b) + " ");
        }
        System.out.println();
    }

    private String bytetoHexString(byte b) {
        // --> obere 3 Byte auf Null setzen und zu String konvertieren
        String ret = Integer.toHexString(b & 0xFF).toUpperCase();
        // ggf. fuehrende Null einfuegen
        ret = (ret.length() < 2 ? "0" : "") + ret;
        return ret;
    }

    private void showErrorAndExit(String msg, Exception ex) {
        System.out.println(msg);
        System.out.println(ex.getMessage());
        System.exit(0);
    }

}
