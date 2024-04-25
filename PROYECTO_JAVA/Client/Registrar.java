import java.io.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;

import javax.crypto.*;

public class Registrar {

    private static String CertStoresPath = "C:/Users/omard/Desktop/Teleco/CUATRI_1/SEG/SEG_B/";
    private static String DocumentsPath = "C:/Users/omard/Desktop/Teleco/CUATRI_1/SEG/SEG_B/PROYECTO_JAVA/Client/Docs_a_enviar/";
    private static String HashesPath = "C:/Users/omard/Desktop/Teleco/CUATRI_1/SEG/SEG_B/PROYECTO_JAVA/Client/HashDocs/";
    

    private static byte[] SignedDoc_temp;
    private static byte[] Doc_temp;

    private static String DocName = null;

    public static MensajeRegistrar_Request Request() {

        FileInputStream InputStreamDoc = null;

        boolean ValidDoc = false;

        //ACCEDEMOS AL DOCUMENTO COMPROBANDO SU CORRECTA LECTURA Y ASEGURANDO QUE NO SUPERA LA LONGITUD MAXIMA REQUERIDA COMO NOMBRE (100 CARACTERES)
        do {

            System.out.println("\nIndica el nombre del documento a registrar: ");

            DocName = SSLSocketClientWithAuth.teclado.nextLine();

            if (DocName.length() >= 100) {

                System.out.println("\nEl nombre del documento debe ser menor a 100 caracteres.");

            } else {

                try {

                    InputStreamDoc = new FileInputStream(DocumentsPath + DocName);
                    ValidDoc = true;
    
                } catch (FileNotFoundException e) {
                    System.out.println("\nNo se ha encontrado el documento. Debe estar situado en " + DocumentsPath + "\n");
                }
            }
 
        } while (!ValidDoc);

        try {

            Doc_temp = InputStreamDoc.readAllBytes();
            InputStreamDoc.close();

        } catch (IOException e) {
            
            System.out.println("\nError en el registro: No se ha podido leer el documento.");
            return null;

        }


        try {
        
            //SE REALIZA EL CIFRADO PGP DEL DOCUMENTO 
            //CIFRADO PGP: CIFRADO DEL DOCUMENTO CON UNA K SECRETA SIMÉTRICA GENERADA Y CIFRADO DE DICHA CLAVE CON LA CLAVE PÚBLICA ASIMÉTRICA DEL CERTIFICADO DE AUTENTICACIÓN DEL RECEPTOR DEL MENSAJE
            //Se genera una K secreta simétrica con el algoritmo AES de 192 bytes de longitud
            KeyGenerator PGPSymmetricKeyGenerator;
            PGPSymmetricKeyGenerator = KeyGenerator.getInstance("AES");
            PGPSymmetricKeyGenerator.init(192);
            SecretKey PGPSymmetricKey = PGPSymmetricKeyGenerator.generateKey();

            //Llamamos a la funcion de cifrado simétrico indicando el modo de operación de cifrado en bloque deseado (CBC)
            Object [] CipheredDocWithPGPObject = Cryptographic_Functions.Cipher_Decipher(true, true, PGPSymmetricKey, Doc_temp, "AES/CBC/PKCS5Padding", null);
            byte [] CipheredDocWithPGP = (byte [])CipheredDocWithPGPObject[0];
            AlgorithmParameters SymmetricPGPParameters = (AlgorithmParameters)CipheredDocWithPGPObject[1];

             
            //Obtenemos del TrustStore la clave pública del certificado de autenticación del servidor 
    		KeyStore ClientTrustStore = KeyStore.getInstance("JCEKS");
            ClientTrustStore.load(new FileInputStream(TrustStoreFIle), StoresPassword);
		    java.security.PublicKey ServerPublicAuthenticationKey = ClientTrustStore.getCertificate("servertls13").getPublicKey();
            

            Object [] CipheredSymmetricKeyPGPObject = Cryptographic_Functions.Cipher_Decipher(true, false, ServerPublicAuthenticationKey, PGPSymmetricKey.getEncoded(), "RSA/ECB/PKCS1Padding", null);
            byte [] CipheredSymmetricKeyPGP = (byte [])CipheredSymmetricKeyPGPObject[0];
            

            //FIRMA DEL DOCUMENTO CON LA CLAVE DE SU CERTIFICADO CORRESPONDIENTE
            //Obtenemos el certificado de firma del KeyStore del cliente y su correspondiente clave privada
            KeyStore ClientKeyStore = KeyStore.getInstance("JCEKS");
            ClientKeyStore.load(new FileInputStream(KeyStoreFile), StoresPassword);

            KeyStore.PrivateKeyEntry ClientSignaturePrivateKeyEntry = (KeyStore.PrivateKeyEntry) ClientKeyStore.getEntry("clientfirma", new KeyStore.PasswordProtection(StoresPassword));
            PrivateKey ClientSignaturePrivateKey = ClientSignaturePrivateKeyEntry.getPrivateKey();
        
            //Obtenemos del KeyStore los certificados de autenticación y firma para su envío
            X509Certificate ClientAuthenticationCertificate = (X509Certificate) ClientKeyStore.getCertificate("clienttls13");
            X509Certificate ClientSignatureCertificate = (X509Certificate) ClientKeyStore.getCertificate("clientfirma");

            //IMPORTANTE: COMPROBAR SI PODEMOS OBTENER EL ALGORITMO DIRECTAMENTE DEL CERTIFICADO, LO MISMO PARA CIFRAR Y DESCIFRAR
            SignedDoc_temp = Cryptographic_Functions.Sign_Document(ClientSignaturePrivateKey, Doc_temp, ClientSignatureCertificate.getEncoded());

            //ENVIAMOS EL MENSAJE
            MensajeRegistrar_Request mensaje = new MensajeRegistrar_Request(DocName, CipheredDocWithPGP, CipheredSymmetricKeyPGP, SymmetricPGPParameters.getEncoded(), SignedDoc_temp, ClientSignatureCertificate.getEncoded(), ClientAuthenticationCertificate.getEncoded());
        
            return mensaje;

        } catch (NoSuchAlgorithmException e) {
        
            System.out.println("\nError en el registro: Algorimo de encriptación desconocido.");
            return null;
        
        } catch (KeyStoreException e) {

            System.out.println("\nError en el registro: No se ha podido acceder al almacén de certificados.");
            return null;
        
        } catch (CertificateException e) {
        
            System.out.println("\nError en el registro: El certificado no es válido.");
            return null;
        
        } catch (FileNotFoundException e) {
        
            System.out.println("\nError en el registro: No se ha podido leer el documento.");
            return null;
        
        } catch (IOException e) {
        
            System.out.println("\nError en el registro: No se ha podido leer el documento.");
            return null;
        
        } catch (UnrecoverableEntryException e) {
        
            System.out.println("\nError en el registro: No se ha podido acceder al almacén de certificados.");
            return null;
        
        }
    }



    public static void Response(MensajeRegistrar_Response respuesta_server) {

        //SE COMPRUEBA SI HA HABIDO ERRORES
        if (respuesta_server.getN_Error() != 0) {

            System.out.println("Codigo de error = " + respuesta_server.getN_Error());

        } else {

            try {

                //SE VERIFICA EL CERTIFICADO DE FIRMA DEL SERVIDOR
                //Obtenemos el nombre del propietario del certificado recibido en el mensaje
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                ByteArrayInputStream ServerSignatureCertificateStream = new ByteArrayInputStream(respuesta_server.getCert_firma());
                X509Certificate ServerSignatureCertificate = (X509Certificate)certFactory.generateCertificate(ServerSignatureCertificateStream);

                //Obtenemos el nombre del propietario del certificado del servidor del truststore y los comparamos
                KeyStore TrustStore_client = KeyStore.getInstance("JCEKS");
                TrustStore_client.load(new FileInputStream(TrustStoreFIle), StoresPassword);
                X509Certificate ServerAuthenticationCertificate = (X509Certificate) TrustStore_client.getCertificate("servertls13");

                if (ServerSignatureCertificate.getSubjectX500Principal().getName().equalsIgnoreCase(ServerAuthenticationCertificate.getSubjectX500Principal().getName()) == false) {

                    System.out.println("CERTIFICADO DE REGISTRADOR INCORRECTO");
                    return;
    
                }

                ByteArrayOutputStream VerificationServerSignature = new ByteArrayOutputStream();
                VerificationServerSignature.write(ByteBuffer.allocate(4).putInt(respuesta_server.getID_registro()).array());
                VerificationServerSignature.write(respuesta_server.getID_propietario().toString().getBytes());
                VerificationServerSignature.write(Doc_temp);
                VerificationServerSignature.write(SignedDoc_temp);

                //Verificar firma del servidor 
                boolean ServerSignatureVerificationResult = Cryptographic_Functions.SignatureVerification(respuesta_server.getFirma_Registrador(), VerificationServerSignature.toByteArray(), ServerSignatureCertificate.getEncoded());
                VerificationServerSignature.close();

                if (ServerSignatureVerificationResult == false) {

                    System.out.println("FIRMA INCORRECTA DEL REGISTRADOR");
                    return;

                }


                System.out.println("Documento registrado correctamente con el numero " + respuesta_server.getID_registro() + "\n");

                File DocSent = new File(DocumentsPath + DocName);
                FileInputStream DocSentStream = new FileInputStream(DocSent);

                MessageDigest MessageDigestInstance = MessageDigest.getInstance("SHA-256");
                MessageDigestInstance.update(DocSentStream.readAllBytes());

                FileOutputStream SaveHash = new FileOutputStream(HashesPath + "hash_" + respuesta_server.getID_registro());
                SaveHash.write(MessageDigestInstance.digest());

                SaveHash.close();
                DocSentStream.close();

                DocSent.delete();
                      
                } catch (CertificateException e) {
                    
                    System.out.println("\nError en la respuesta del registro: Certificado no válido.");
                    return;

                } catch (KeyStoreException e) {
                    
                    System.out.println("\nError en la respuesta del registro: No se ha podido acceder al almacén de certificados.");
                    return;
        
                } catch (NoSuchAlgorithmException e) {
                    
                    System.out.println("\nError en la respuesta del registro: Algoritmo desconocido.");
                    return;

                } catch (FileNotFoundException e) {
                    
                    System.out.println("\nError en la respuesta del registro: No se ha podido acceder al archivo.");
                    return;

                } catch (IOException e) {
                    
                    System.out.println("\nError en la respuesta del registro: No se ha podido acceder al archivo.");
                    return;

                }
        }

        return; 

    }


    /******************************************************
	* DefinedKeyStores()
	*****************************************************/
    private static String KeyStoreFile   = CertStoresPath + "ClientKeystore.jce";
    private static String TrustStoreFIle = CertStoresPath + "ClientTruststore.jce";
    private static char[] StoresPassword = "seg2223".toCharArray();

	private static void DefinedKeyStores() {

		// Almacen de credenciales
		System.setProperty("javax.net.ssl.keyStore", KeyStoreFile);
		System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.keyStorePassword", "seg2223");

		// Almacen de confianza
		System.setProperty("javax.net.ssl.trustStore", TrustStoreFIle);
		System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.trustStorePassword", "seg2223");

	}
    
}
