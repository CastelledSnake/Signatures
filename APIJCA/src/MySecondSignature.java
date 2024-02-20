import java.nio.charset.StandardCharsets;
import java.security.Signature;

import util.ByteToHex;

public class MySecondSignature extends MyFirstSignature {

    private final String pNomAlgo = "SHA256withRSA";
    public MySecondSignature(String message) {
        super(message);
    }

    @Override
    public byte[] sign() {
        byte[] signature = null;
        try {
            Signature sign = Signature.getInstance(this.pNomAlgo);
            sign.initSign(this.privateKey);
            sign.update(this.myMessage.getBytes(StandardCharsets.UTF_8));
            signature = sign.sign();
            return signature;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public boolean verifySignature(byte[] pCondensat) {
        try {
            Signature sign = Signature.getInstance(this.pNomAlgo);
            sign.initVerify(this.publicKey);
            sign.update(this.myMessage.getBytes(StandardCharsets.UTF_8));
            return sign.verify(pCondensat);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public static void main(String [] args) {
        String message = "Je signe un message électroniquement";
        // Signature du message
        MySecondSignature mySecondSignature = new MySecondSignature(message);
        byte[] signature = mySecondSignature.sign();
        System.out.println("Signature : " + ByteToHex.convert(signature));

        // Vérification de la signature
        boolean lvalide = mySecondSignature.verifySignature(signature);
        System.out.println("La signature est " + (lvalide ? "valide" : "invalide"));
    }
}
