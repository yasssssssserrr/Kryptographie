package Praktikum3;

import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.PKCS8EncodedKeySpec;

public class RSAKeyCreation {

    // die Laenge des Schluessels
    private static final int schluesselLaenge = 4096;

    // der Inhabername
    private static String inhaberName = null;

    // das Schluesselpaar
    private static KeyPair schluesselPaare = null;

    public static KeyPair getKeyPair() {
        return schluesselPaare;
    }

    /**
     * Diese Methode generiert ein neues Schluesselpaar.
     */
    public static void generateKeyPair() {
        try {
            // als Algorithmus verwenden wir RSA
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");

            // mit gewuenschter Schluessellaenge initialisieren
            gen.initialize(schluesselLaenge);
            schluesselPaare = gen.generateKeyPair();

        } catch (NoSuchAlgorithmException ex) {
            System.err.println("RSA Algorithmus existiert nicht!");
            System.exit(0);
        }
    }

    /**
     * Speichert den oeffentlichen Schluessel in Datei <Inhabername>.pub,  public = true, private = false
     * ansonsten privaten Schluessel in Datei <Inhabername>.prv
     */
    public static void saveKeyInFile(boolean pub) {

        String fileName = pub ? String.format(System.getProperty("user.dir") + "/%s.pub", inhaberName)
                : String.format(System.getProperty("user.dir") + "/%s.prv", inhaberName);

        // der oeffentliche bzw. private Schluessel vom Schluesselpaar
        Key key = pub ? schluesselPaare.getPublic() : schluesselPaare.getPrivate();

        // wir benoetigen die Bytefolge im Default-Format
        byte[] keyBytes = key.getEncoded(); //X.509

        // PKCS8-Format fuer privaten Schluessel
        if (!pub) {
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
            keyBytes = pkcs8EncodedKeySpec.getEncoded();
        }

        try {
            // eine Datei wird erzeugt und danach folgendes darin gespeichert:
            // 1. Laenge des Inhaber-Namens (integer)
            // 2. Inhaber-Name (Bytefolge)
            // 3. Laenge des Schluessels (integer)
            // 4. oeffentlicher Schluessel (Bytefolge) [X.509-Format] bzw. privater Schluessel (Bytefolge) [PKCS8-Format]
            DataOutputStream os = new DataOutputStream(new FileOutputStream(fileName));
            os.writeInt(inhaberName.length());
            os.write(inhaberName.getBytes());
            os.writeInt(keyBytes.length);
            os.write(keyBytes);
            os.close();

        } catch (IOException ex) {
            System.out.printf("Fehler beim Schreiben in der Datei %s%n", fileName);
            System.exit(0);
        }

        // Bildschirmausgabe
        System.out.println("Der Key wurde in folgendem Format gespeichert: " + key.getFormat());
        byteArraytoHexString(keyBytes);
        System.out.println();
    }

    /**
     * Konvertiert ein Byte-Array in einen Hex-String.
     */

    private static void byteArraytoHexString(byte[] byteArray) {
        for (int i = 0; i < byteArray.length; ++i) {
            System.out.print(bytetoHexString(byteArray[i]) + " ");
        }
        System.out.println();
    }

    private static String bytetoHexString(byte b) {
        // --> obere 3 Byte auf Null setzen und zu String konvertieren
        String ret = Integer.toHexString(b & 0xFF).toUpperCase();
        // ggf. fuehrende Null einfuegen
        ret = (ret.length() < 2 ? "0" : "") + ret;
        return ret;
    }


    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java RSAKeyCreation Inhabername");
        } else {
            inhaberName = args[0];

            // die Schluessel generieren
            generateKeyPair();

            // den oeffentlichen Schluessel in Datei <Inhabername>.pub speichern
            saveKeyInFile(true);

            // den privaten Schluessel in Datei <Inhabername>.prv speichern
            saveKeyInFile(false);
        }
    }
}
