import com.itextpdf.text.Document;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfWriter;
import com.itextpdf.text.pdf.security.*;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Collections;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class MySignaturePdf {

    private PrivateKey privateKey;
    private java.security.cert.Certificate[] certificateChain;

    public MySignaturePdf(String pP12File, String pMotDePasse) throws KeyStoreException, NoSuchProviderException, IOException, CertificateException, NoSuchAlgorithmException {
        // Le manageur crypto BouncyCastle est ajouté comme fournisseur de sécurité
        Security.addProvider(new BouncyCastleProvider());
        KeyStore keystore = KeyStore.getInstance("pkcs12", "BC");
        // Chargement du fichier avec le mot de passe en 2ème paramètre
        keystore.load(new FileInputStream(pP12File), pMotDePasse.toCharArray());
        Enumeration<String> lAliases = keystore.aliases();
        Collections.list(lAliases).forEach(alias -> {
            try {
                if (keystore.isKeyEntry(alias)) {
                    try {
                        this.privateKey = (PrivateKey) keystore.getKey(alias, pMotDePasse.toCharArray());
                        certificateChain = keystore.getCertificateChain(alias);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            } catch (KeyStoreException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public void generatePdf() {
        // Création du document.
        Document document = new Document();
        try {
            // Assignation du type du document et du chemin de sauvegarde.
            PdfWriter.getInstance(document, new FileOutputStream("text.pdf"));
            // Ouverture du document et ajout d'un paragraphe.
            document.open();
            document.add(new Paragraph("Je vais signer un fichier PDF"));
            document.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void apposerSignature(String pSourceFile, String pDestFile, String pRaisonSignature, String pMaVille, String pMonEcole) {
        try {
            // Lecteur du fichier source depuis le système de fichiers
            PdfReader reader = new PdfReader(pSourceFile);
            FileOutputStream os = new FileOutputStream(pDestFile);
            // Initialisation du tampon de signature
            PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
            // Apparence de la signature (on aurait pu ajouter une image)
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
            // Raison de la signature du document
            appearance.setReason(pRaisonSignature);
            // Lieu de la signature
            appearance.setLocation(pMonEcole + " " + pMaVille);
            // Positionnement dans un rectangle de la signature visible demandée
            appearance.setVisibleSignature(new Rectangle(52, 692, 234, 760), 1, "first");
            // Initialisation de l’algorithme de hash sha256, de la clé privée du signataire et du fournisseur de sécurité, ici Bouncy Castle
            ExternalSignature es = new PrivateKeySignature(this.privateKey, "SHA-256", "BC");
            ExternalDigest digest = new BouncyCastleDigest();
            // Application de la signature au PDF cible avec la chaine de certification au format CADES
            MakeSignature.signDetached(appearance, digest, es, this.certificateChain, null, null, null, 0,
                    MakeSignature.CryptoStandard.CMS);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

        public static void main(String[] args) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, NoSuchProviderException {
        MySignaturePdf mySignaturePdf = new MySignaturePdf("PrenomNom_cert_sign.p12", "toto");
        mySignaturePdf.generatePdf();
        mySignaturePdf.apposerSignature("text.pdf", "text_signed.pdf", "Réalisation d'un TP", "Brest", "ENSTA Bretagne");
    }
}