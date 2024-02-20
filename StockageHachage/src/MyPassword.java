import java.nio.charset.StandardCharsets;
import java.util.Scanner;
import java.security.MessageDigest;

import util.ByteToHex;

public class MyPassword {
    private final String password;

    private MyPassword(String password) {
        byte[] hash = hacheSha256(password);
        this.password = ByteToHex.convert(hash);
    }

    public String getPassword() {
        return this.password;
    }

    @Override
    public String toString() {
        return "Mot de passe stocké : " + this.password;
    }

    public static byte[] hacheSha256(String pMessage) {
        try {
            /* Création de l'objet MessageDigest en SHA-256 */
            MessageDigest lDigest = MessageDigest.getInstance("SHA-256");
            /* Génération du haché en passant pMessage à lDigest, préalablement converti en tableau d'entiers UTF-8 */
            lDigest.update(pMessage.getBytes(StandardCharsets.UTF_8));
            return lDigest.digest();
        } catch (Exception e) {
            e.printStackTrace();
    }
        /* Dans les faits, il est très peu probable que la méthode retourne null. */
        return null;
    }

    @Override
    public boolean equals(Object pPass) {
        return this.password.equals(((MyPassword) pPass).getPassword());
    }

    public boolean controleAcces(String pPass) {
        MyPassword myPasswordControleAcces = new MyPassword(pPass);
        return this.equals(myPasswordControleAcces);
    }

    public static void main(String[] args) {
        // Demande le mot de passe à l'utilisateur.
        System.out.println("Veuillez définir un mot de passe : ");
        Scanner scanneur = new Scanner(System.in);
        String passString = scanneur.nextLine();
        // Stocke le haché du mot de passe rentré.
        MyPassword myPassword = new MyPassword(passString);
        System.out.println(myPassword);

        // Demande à l'utilisateur de rentrer un mot de passe pour contrôler son identité.
        System.out.println("Veuillez saisir votre mot de passe pour vous connecter : ");
        String passTest = scanneur.nextLine();
        System.out.println(myPassword.controleAcces(passTest) ? "Succès" : "Échec");

        scanneur.close();
    }
}