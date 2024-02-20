import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;

import util.ByteToHex;

public class MyFirstSignature {

    protected String myMessage;
    protected PrivateKey privateKey;
    protected PublicKey publicKey;

    public MyFirstSignature(String message) {
        myMessage = message;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();
            this.privateKey = keyPair.getPrivate();
            System.out.println("Clef Privée : " + this.privateKey);
            this.publicKey = keyPair.getPublic();
            System.out.println("Clef Publique : " + this.publicKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private byte[] encrypt(byte[] pTabSig) {
        byte[] encrypted = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, this.privateKey);
            encrypted = cipher.doFinal(pTabSig);
            return encrypted;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private byte[] decrypt(byte[] pCondensat) {
        byte[] decrypted = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, this.publicKey);
            decrypted = cipher.doFinal(pCondensat);
            return decrypted;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] sign() {
        byte[] signature = null;
        try {
            signature = encrypt(this.myMessage.getBytes(StandardCharsets.UTF_8));
            return signature;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean verifySignature(byte[] pCondensat) {
        byte[] decrypted = decrypt(pCondensat);
        return this.myMessage.equals(new String(decrypted));
    }

    public static void main(String[] args) {
        MyFirstSignature myFirstSignature = new MyFirstSignature("Je signe un message électroniquement");
        // Sauvegarde de la signature
        byte[] lFirstSignature = myFirstSignature.sign();
        // Affichage de la signature
        System.out.println("La signature du message: [Je signe un message électroniquement] est :\n" +
                ByteToHex.convert(lFirstSignature));

        // Vérification de la signature
        boolean lValide = myFirstSignature.verifySignature(lFirstSignature);
        System.out.println( "La signature est " + (lValide ? "Valide" : "Invalide"));
    }
}