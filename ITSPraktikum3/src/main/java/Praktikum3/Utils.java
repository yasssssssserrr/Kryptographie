package Praktikum3;

public class Utils {


    /**
     * Konvertiert ein Byte-Array in einen Hex-String.
     */
    public static void byteArraytoHexString(byte[] byteArray) {
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


    /**
     * Concatenate two byte arrays
     */
    public static byte[] concatenate(byte[] ba1, byte[] ba2) {
        int len1 = ba1.length;
        int len2 = ba2.length;
        byte[] result = new byte[len1 + len2];

        // Fill with first array
        System.arraycopy(ba1, 0, result, 0, len1);
        // Fill with second array
        System.arraycopy(ba2, 0, result, len1, len2);

        return result;
    }
}
