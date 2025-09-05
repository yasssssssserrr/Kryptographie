package Praktikum3;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSF {

    private PublicKey pubKey;
    private PrivateKey prvKey;
    private final String sender;
    private final String empfaenger;
    private final String entschluesseltFileName;
    private final String verschluesseltFileName;
    private final int bufferSize;
    private byte[] decryptedSecretKeyBytes;
    private byte[] secretKeySignature;

    public RSF(String sender, String empfaenger, String verschluesseltFileName, String entschluesseltFileName, int bufferSize) {
        this.sender = sender;
        this.empfaenger = empfaenger;
        this.entschluesseltFileName = entschluesseltFileName;
        this.verschluesseltFileName = verschluesseltFileName;
        this.bufferSize = bufferSize;
    }

    public RSF(String sender, String empfaenger, String verschluesseltFileName, String entschluesseltFileName) {
        this(sender, empfaenger, verschluesseltFileName, entschluesseltFileName, 1024);
    }


    // 3.a/b
    public void setFileKeys(String filePath) {
        try {

            // Informationen aus der Datei lesen
            DataInputStream in = new DataInputStream(new FileInputStream(filePath));
            int len = in.readInt();
            byte[] InhaberName = new byte[len];
            in.read(InhaberName);
            len = in.readInt();
            byte[] fileKey = new byte[len];
            in.read(fileKey);

            KeyFactory keyFac = KeyFactory.getInstance("RSA");
            if (filePath.endsWith(".pub")) {

                // aus dem Byte-Array koennen wir eine X.509-Schluesselspezifikation erzeugen
                X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(fileKey);

                // nun wird aus der Spezifikation wieder abgeschlossener public key erzeugt
                pubKey = keyFac.generatePublic(x509KeySpec);

            } else {

                // aus dem Byte-Array koennen wir eine X.509-Schluesselspezifikation erzeugen
                PKCS8EncodedKeySpec Pkcs8KeySpec = new PKCS8EncodedKeySpec(fileKey);

                // nun wird aus der Spezifikation wieder abgeschlossener public key erzeugt
                prvKey = keyFac.generatePrivate(Pkcs8KeySpec);
            }

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    // 3.c.
    public void readAndDecryptFile() {
        try {
            // Informationen aus Datei lesen
            System.out.println("Lese verschluesselte Datei: " + verschluesseltFileName + " ...");
            DataInputStream in = new DataInputStream(new FileInputStream(verschluesseltFileName));

            int len = in.readInt();
            byte[] encryptedSecretKey = new byte[len];
            in.read(encryptedSecretKey);

            len = in.readInt();
            secretKeySignature = new byte[len];
            in.read(secretKeySignature);

            len = in.readInt();
            byte[] parameters = new byte[len];
            in.read(parameters);

            // geheimen Schlüssel mit dem privaten RSA-Schlüssel entschlüsseln
            decryptedSecretKeyBytes = decryptSecretKey(encryptedSecretKey);
            Cipher aesCipher = createAESCipher(decryptedSecretKeyBytes, parameters);

            // gibt die entschlüsselte Datei aus
            System.out.println("Schreibe entschluesselte Datei: " + entschluesseltFileName + " ...");
            DataOutputStream out = new DataOutputStream(new FileOutputStream(entschluesseltFileName));

            byte[] inBuffer = new byte[bufferSize];
            while ((len = in.read(inBuffer, 0, inBuffer.length)) > 0) {
                byte[] result = aesCipher.update(inBuffer, 0, len);
                out.write(result);
            }
            in.close();

            // mit doFinal abschliessen (Rest inkl. Padding ..)
            byte[] resultRest = aesCipher.doFinal();
            if (resultRest.length > 0) out.write(resultRest);
            out.close();

        } catch (IOException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    // 3.d.
    private void validateSignature() {
        try {
            Signature rsaSignatur = Signature.getInstance("SHA512withRSA");
            rsaSignatur.initVerify(pubKey);
            rsaSignatur.update(decryptedSecretKeyBytes);
            boolean signatureBoolean = rsaSignatur.verify(secretKeySignature);
            if (signatureBoolean) {
                System.out.println("Signatur wurde erfolgreich verifiziert!");
            } else {
                System.out.println("Fehler: Signatur konnte nicht verifiziert werden!");
            }
        } catch (NoSuchAlgorithmException ex) {
            System.out.println("Implementierung fuer SHA256withRSA nicht moeglich! Algorithmus nicht gefunden.");
        } catch (SignatureException ex) {
            System.out.println("Fehler beim ueberpruefen der Signatur!");
        } catch (InvalidKeyException ex) {
            System.out.println("Falscher / Ungueltiger Schluessel!");
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

    private byte[] decryptSecretKey(byte[] encryptedSecretKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");

            // Initialisierung zur Verschluesselung mit automatischer Parametererzeugung
            cipher.init(Cipher.DECRYPT_MODE, prvKey);

            byte[] processedData = cipher.update(encryptedSecretKey);
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

    private Cipher createAESCipher(byte[] decryptedSecretKeyBytes, byte[] parameters) {
        Cipher cipher;
        try {
            SecretKeySpec skspec = new SecretKeySpec(decryptedSecretKeyBytes, "AES");
            AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("AES");
            algorithmParameters.init(parameters);
            cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, skspec, algorithmParameters);

        } catch (NoSuchAlgorithmException | IOException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }

        return cipher;
    }

    public String getSender() {
        return sender;
    }

    public String getReceiver() {
        return empfaenger;
    }


    public static void main(String[] args) {

        // RSF-Entschluesselung initialisiert
        RSF rsf = new RSF(args[0], args[1], args[2], args[3]);

        // nimmt public und private key vom Sender und Empfänger
        String currentDir = "C:\\Users\\Yasser Ibourk\\Desktop\\ITSPraktikum2\\src\\main\\java\\Praktikum3";
        rsf.setFileKeys(currentDir + "\\"+ rsf.sender);
        rsf.setFileKeys(currentDir + "\\"+rsf.empfaenger);

        // RSF-Entschlüsselung gestartet
        rsf.readAndDecryptFile();

        // Signatur wird validiert / ueberprueft
        rsf.validateSignature();

    }

}
