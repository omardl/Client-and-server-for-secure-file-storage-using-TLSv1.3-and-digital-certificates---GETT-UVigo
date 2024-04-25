import java.io.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Recuperar {

    private static String CertStoresPath = "C:/Users/omard/Desktop/Teleco/CUATRI_1/SEG/SEG_B/";
    private static String DocumentsPath = "C:/Users/omard/Desktop/Teleco/CUATRI_1/SEG/SEG_B/PROYECTO_JAVA/Client/RecoveredDocs/";
    private static String HashesPath = "C:/Users/omard/Desktop/Teleco/CUATRI_1/SEG/SEG_B/PROYECTO_JAVA/Client/HashDocs/";
    
    public static RecuperarDocumento_Request Request() {

        try {

            //Obtenemos el certificado de autenticación del cliente
            KeyStore ClientKeyStore = KeyStore.getInstance("JCEKS");
            ClientKeyStore.load(new FileInputStream(KeyStoreFile), StoresPassword);
            X509Certificate ClientAuthenticationCertificate = (X509Certificate) ClientKeyStore.getCertificate("clienttls13");

            //Obtenemos el id de registro del documento a recuperar
            System.out.println("\nIndica el ID del documento a recuperar: ");
            String ID_teclado = SSLSocketClientWithAuth.teclado.nextLine();

            int ID_Reg = Integer.parseInt(ID_teclado);

            RecuperarDocumento_Request RequestMessage = new RecuperarDocumento_Request(ClientAuthenticationCertificate.getEncoded(), ID_Reg);
            return RequestMessage;

        } catch (KeyStoreException | NoSuchAlgorithmException |CertificateException | IOException e) {

            System.out.println("\nError al intentar recuperar el documento: El cliente no ha podido obtener su certificado del KeyStore.");

        } 

        return null;
    }


    public static void Response(RecuperarDocumento_Response ResponseMessage) {
        
        try {

            //SE VERIFICA EL CERTIFICADO DE FIRMA DEL SERVIDOR
            //Obtenemos el nombre del propietario del certificado recibido en el mensaje
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream ServerSignatureCertificateStream = new ByteArrayInputStream(ResponseMessage.getServerSignatureCertificate());
            X509Certificate ServerSignatureCertificate = (X509Certificate)certFactory.generateCertificate(ServerSignatureCertificateStream);
        
            //Obtenemos el nombre del propietario del certificado del servidor del truststore y los comparamos
            KeyStore ClientTrustStore = KeyStore.getInstance("JCEKS");
            ClientTrustStore.load(new FileInputStream(TrustStoreFile), StoresPassword);
            X509Certificate ServerAuthenticationCertificate = (X509Certificate) ClientTrustStore.getCertificate("servertls13");

            if (ServerSignatureCertificate.getSubjectX500Principal().getName().equalsIgnoreCase(ServerAuthenticationCertificate.getSubjectX500Principal().getName()) == false) {

                System.out.println("CERTIFICADO DE REGISTRADOR INCORRECTO");
                return;
    
            }

            //SE REALIZA EL DESCIFRADO PGP
            //Se obtiene la clave privada de autenticación del cliente para descifrar K
            KeyStore ClientKeyStore = KeyStore.getInstance("JCEKS");
            ClientKeyStore.load(new FileInputStream(KeyStoreFile), StoresPassword);

            KeyStore.PrivateKeyEntry ClientAutenticationPrivateKeyEntry = (KeyStore.PrivateKeyEntry) ClientKeyStore.getEntry("clienttls13", new KeyStore.PasswordProtection(StoresPassword));
            PrivateKey ClientAutenticationPrivateKey = ClientAutenticationPrivateKeyEntry.getPrivateKey();

            Object [] DecypheredSecretKeyPGPObject = Cryptographic_Functions.Cipher_Decipher(false, false, ClientAutenticationPrivateKey, ResponseMessage.getCipheredSymmetricKeyPGP(), "RSA/ECB/PKCS1Padding", null);
            SecretKey DecypheredSecretKeyPGP = new SecretKeySpec((byte [])DecypheredSecretKeyPGPObject[0], "AES");

            //Obtenida K, se realiza el descifrado PGP del documento
            Object [] DecypheredDocPGPObject = Cryptographic_Functions.Cipher_Decipher(false, true, DecypheredSecretKeyPGP, ResponseMessage.getCipheredDocWithPGP(), "AES/CBC/PKCS5Padding", ResponseMessage.getCipherParams());
            byte [] DecypheredDoc = (byte []) DecypheredDocPGPObject[0];
            
            //SE VERIFICA LA FIRMA
            ByteArrayOutputStream VerificationSignatureServer = new ByteArrayOutputStream();
            VerificationSignatureServer.write(ByteBuffer.allocate(4).putInt(ResponseMessage.getID_registro()).array());
            VerificationSignatureServer.write(ResponseMessage.getID_Owner().toString().getBytes());
            VerificationSignatureServer.write(DecypheredDoc);

            KeyStore.PrivateKeyEntry ClientSignaturePrivateKeyEntry = (KeyStore.PrivateKeyEntry) ClientKeyStore.getEntry("clientfirma", new KeyStore.PasswordProtection(StoresPassword));
            PrivateKey ClientSignaturePrivateKey = ClientSignaturePrivateKeyEntry.getPrivateKey();
            X509Certificate ClientSignatureCertificate = (X509Certificate) ClientKeyStore.getCertificate("clientfirma");
            VerificationSignatureServer.write(Cryptographic_Functions.Sign_Document(ClientSignaturePrivateKey, DecypheredDoc, ClientSignatureCertificate.getEncoded()));

    
            boolean VerificationCorrect = Cryptographic_Functions.SignatureVerification(ResponseMessage.getServerSignature(), VerificationSignatureServer.toByteArray(), ServerSignatureCertificate.getEncoded());
            VerificationSignatureServer.close();

             
            if(!VerificationCorrect) {
                System.out.println("ERROR DE FIRMA DEL REGISTRADOR. je ");
                return;
            }

            
            //SE COMPUTA EL HASH Y SE CONTRASTA CON EL ALMACENADO
            MessageDigest MessageDigestInstance = MessageDigest.getInstance("SHA-256");
            MessageDigestInstance.update(DecypheredDoc);
            byte [] HashToVerify = MessageDigestInstance.digest();

            FileInputStream HashStoredStream = new FileInputStream(HashesPath + "hash_" + ResponseMessage.getID_registro());
            byte [] HashStored = HashStoredStream.readAllBytes();
            HashStoredStream.close();

            if (Arrays.compare(HashToVerify, HashStored) != 0) {
                System.out.println("\nDOCUMENTO MODIFICADO.");
                return;
            }

            File RecoveredDoc = new File(DocumentsPath + "Recovered_id" + ResponseMessage.getID_registro() + "_" + ResponseMessage.getDocName());
            FileOutputStream RecoveredDocStream = new FileOutputStream(RecoveredDoc);
            RecoveredDocStream.write(DecypheredDoc);
            RecoveredDocStream.close();

            System.out.println("\nDocumento recuperado correctamente.\n");
            return;

        } catch (CertificateException | KeyStoreException | NoSuchAlgorithmException | IOException e) {

            System.out.println("Error al procesar la respuesta del servidor al recuperar documento: No se ha podido acceder al certificado del servidor del TrustStore.");

        } catch (UnrecoverableEntryException e) {
            
            System.out.println("Error al procesar la respuesta del servidor al recuperar documento: No se ha podido acceder al certificado de autenticación del cliente.");
            
        }
        

        
    }

    /******************************************************
	* DefinedKeyStores()
	*****************************************************/
    private static String KeyStoreFile   = CertStoresPath + "ClientKeystore.jce";
    private static String TrustStoreFile = CertStoresPath + "ClientTruststore.jce";
    private static char[] StoresPassword = "seg2223".toCharArray();

	private static void DefinedKeyStores() {

		// Almacen de credenciales
		System.setProperty("javax.net.ssl.keyStore", KeyStoreFile);
		System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.keyStorePassword", "seg2223");

		// Almacen de confianza
		System.setProperty("javax.net.ssl.trustStore", TrustStoreFile);
		System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.trustStorePassword", "seg2223");

	}
}
