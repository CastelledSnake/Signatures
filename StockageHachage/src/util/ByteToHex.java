package util;

import java.util.Formatter;

public class ByteToHex {
    /**
     * Convertit un tableau de bytes en chaine hexadécimal
     */
    public static String convert(byte[] pTabBytes) {
        Formatter formatter = new Formatter();
        for ( byte b : pTabBytes ) {
            formatter.format("%02x", b);
        }
        String lString = formatter.toString();
        formatter.close();
        return lString;
    }
}