import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.KeyStore.SecretKeyEntry;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import javax.swing.SpringLayout.Constraints;
import javax.swing.plaf.basic.BasicSplitPaneUI.BasicHorizontalLayoutManager;

public abstract class ClassServer implements Runnable {

    private static String CertStoresPath = "C:/Users/omard/Desktop/Teleco/CUATRI_1/SEG/SEG_B/";
    private static String DocumentsPath = "C:/Users/omard/Desktop/Teleco/CUATRI_1/SEG/SEG_B/PROYECTO_JAVA/DirectorioArquivos/";

    SecretKey ServerSecretKey = null;

    int id_registro = 0;

    private ServerSocket server = null;
    /**
     * Constructs a ClassServer based on <b>ss</b> and
     * obtains a file's bytecodes using the method <b>getBytes</b>.
     *
     */
    protected ClassServer(ServerSocket ss)
    {
        server = ss;
        newListener();
    }

    /**
     * Returns an array of bytes containing the bytes for
     * the file represented by the argument <b>path</b>.
     *
     * @return the bytes for the file
     * @exception FileNotFoundException if the file corresponding
     * to <b>path</b> could not be loaded.
     * @exception IOException if error occurs reading the class
     */
    public abstract byte[] getBytes(String path) throws IOException, FileNotFoundException;

    /**
     * The "listen" thread that accepts a connection to the
     * server, parses the header to obtain the file name
     * and sends back the bytes for the file (or error
     * if the file is not found or the response was malformed).
     */

    public void run() {

        Socket socket;

        // accept a connection
        try {
        
            socket = server.accept();
            System.out.println("\nSe ha conectado un nuevo cliente.\n");
        
        } catch (IOException e) {
        
            System.out.println("Class Server died: " + e.getMessage());
            e.printStackTrace();
            return;
        }

        // create a new thread to accept the next connection
        newListener();

        try {

            //Dos canales de salida sobre el socket: binario (rawOut) y de texto (out)
            OutputStream rawOut = socket.getOutputStream();
            PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(rawOut)));
            ObjectOutputStream salida = new ObjectOutputStream(rawOut);

            InputStream entrada = socket.getInputStream();
            BufferedReader in = new BufferedReader(new InputStreamReader(entrada)); 
            ObjectInputStream datos = new ObjectInputStream(entrada);
            
            try {

                try {

                    boolean salida_bucle = false;

                    while (!salida_bucle) {
    
                        String OperationMode = in.readLine().trim();


                        if (OperationMode.contains("REGISTRAR")) {

                            int RegisterID = 0;
                            X500Principal OwnerID;

                            MensajeRegistrar_Request mensaje_recibido = (MensajeRegistrar_Request) datos.readObject();

                            //SE VALIDA EL CERTIFICADO DE FIRMA 
                            //Se comprueba que las identidades de los propietarios de ámbos certificados recibidos son la misma
                            CertificateFactory CertificateFactoryInstance = CertificateFactory.getInstance("X.509");
                        
                            ByteArrayInputStream ClientSignatureCertificateStream = new ByteArrayInputStream(mensaje_recibido.getCertificadoFirmaC());
                            ByteArrayInputStream ClientAuthenticationCertificateStream = new ByteArrayInputStream(mensaje_recibido.getCertificadoCifradoC());
                        
                            X509Certificate ClientSignatureCertificate = (X509Certificate)CertificateFactoryInstance.generateCertificate(ClientSignatureCertificateStream);                       
                            X509Certificate ClientAuthenticationCertificate = (X509Certificate)CertificateFactoryInstance.generateCertificate(ClientAuthenticationCertificateStream);

                            if (ClientSignatureCertificate.getSubjectX500Principal().getName().equals(ClientAuthenticationCertificate.getSubjectX500Principal().getName()) == false) {

                                System.out.println("\nCERTIFICADO DE FIRMA INCORRECTO.");

                                MensajeRegistrar_Response mensaje_respuesta = new MensajeRegistrar_Response(1);
                                salida.writeObject(mensaje_respuesta);
                                salida.flush();

                            } else {        

                                //SE VERIFICA LA FIRMA
                                OwnerID = ClientAuthenticationCertificate.getSubjectX500Principal();

                                //Obtenemos primero el documento descifrado, empezando por descifrar la clave simétrica con la clave privada del servidor
                                KeyStore ServerKeystore = KeyStore.getInstance("JCEKS");
                                ServerKeystore.load(new FileInputStream(KeyStoreFile), StoresPassword);
                                KeyStore.PrivateKeyEntry ServerPrivateAuthenticationKeyEntry = (KeyStore.PrivateKeyEntry) ServerKeystore.getEntry("servertls13", new KeyStore.PasswordProtection(StoresPassword));
                                PrivateKey ServerPrivateAuthenticationKey = ServerPrivateAuthenticationKeyEntry.getPrivateKey();
                            
                                Object [] SymmetricKeyPGPObject = Cryptographic_Functions.Cipher_Decipher(false, false, ServerPrivateAuthenticationKey, mensaje_recibido.getClaveSimetricaCifrada(), "RSA/ECB/PKCS1Padding", null);
                                SecretKey SymmetricKeyPGP = new SecretKeySpec((byte [])SymmetricKeyPGPObject[0], "AES");
  

                                //Una vez obtenida la clave simétrica desciframos el document
                                Object [] ClearDocObject = Cryptographic_Functions.Cipher_Decipher(false, true, SymmetricKeyPGP, mensaje_recibido.getDocumentoCifrado(), "AES/CBC/PKCS5Padding", mensaje_recibido.getParametrosCifrado());
                                byte [] ClearDoc = (byte [])ClearDocObject[0];
                            
                                //LLamamos a la funcion de verificacion de firma
                                boolean verification_result = Cryptographic_Functions.SignatureVerification(mensaje_recibido.getFirmaDocumento(), ClearDoc, ClientSignatureCertificate.getEncoded());

                                if (verification_result == false) {

                                    MensajeRegistrar_Response mensaje_respuesta = new MensajeRegistrar_Response(1);
                                    salida.writeObject(mensaje_respuesta);
                                    salida.flush();
                                    System.out.println("\nFirma incorrecta.\n");

                                    return;

                                } 
                            
                                //CAMBIAR ESTA PARTE EN EL FUTURO, DEBE SER SIEMPRE LA MISMA K

                                if (ServerSecretKey == null) {

                                    //Algoritmo distinto a AES
                                    KeyGenerator ServerKeyGenerator = KeyGenerator.getInstance("DES");
                                    //Clave de 196 bits de longitud
                                    ServerKeyGenerator.init(56);
                                    ServerSecretKey = ServerKeyGenerator.generateKey();
                                }
                                
                                Object [] FinalCipheredDocObject = Cryptographic_Functions.Cipher_Decipher(true, true, ServerSecretKey, ClearDoc, "DES/CFB/PKCS5Padding", null);
                                byte [] CipheredDoc = (byte []) FinalCipheredDocObject[0];
                                AlgorithmParameters ServerSecretKeyParameters = (AlgorithmParameters) FinalCipheredDocObject[1];                                
                                

                                //Firma del registrador: id_registro, id_propietario, documento, firma_doc
                                ByteArrayOutputStream FinalSignatureStream = new ByteArrayOutputStream();
                                FinalSignatureStream.write(ByteBuffer.allocate(4).putInt(id_registro).array());
                                FinalSignatureStream.write(OwnerID.toString().getBytes());
                                FinalSignatureStream.write(ClearDoc);
                                FinalSignatureStream.write(mensaje_recibido.getFirmaDocumento());
                            

                                KeyStore.PrivateKeyEntry ServerSignaturePrivateKeyEntry = (KeyStore.PrivateKeyEntry) ServerKeystore.getEntry("serverfirma", new KeyStore.PasswordProtection(StoresPassword));
                                PrivateKey ServerSignaturePrivateKey = ServerSignaturePrivateKeyEntry.getPrivateKey();
                                X509Certificate ServerSignatureCertificate = (X509Certificate) ServerKeystore.getCertificate("serverfirma");

                                byte [] FinalSignature = Cryptographic_Functions.Sign_Document(ServerSignaturePrivateKey, FinalSignatureStream.toByteArray(), ServerSignatureCertificate.getEncoded());
                                FinalSignatureStream.close();


                                //Guardar en un archivo documento cifrado, firma, Id registro, timestamp y firma del registrador.
                                //A mayores se ha decidido guardar: los parametros de cifrado simetrico del documento, el nombre original del documento y la cantidad de bytes que ocupa dicho nombre
                                String FileName = id_registro + "_" + OwnerID.getName() + ".sig.cif";

                                FileOutputStream StoreFile = new FileOutputStream(FileName);
                                StoreFile.write(CipheredDoc);
                                StoreFile.write(mensaje_recibido.getFirmaDocumento());
                                StoreFile.write(ByteBuffer.allocate(4).putInt(id_registro).array());
                                Timestamp ts = new Timestamp(System.currentTimeMillis());
                                StoreFile.write(ts.toString().getBytes());
                                StoreFile.write(FinalSignature);
                                StoreFile.write(mensaje_recibido.getNombreDoc().getBytes());
                                StoreFile.write(ByteBuffer.allocate(4).putInt(mensaje_recibido.getNombreDoc().getBytes().length).array());
                                StoreFile.write(ServerSecretKeyParameters.getEncoded());
                                StoreFile.write(ByteBuffer.allocate(4).putInt(ServerSecretKeyParameters.getEncoded().length).array());
                                StoreFile.close();
                        
                                MensajeRegistrar_Response mensaje_respuesta = new MensajeRegistrar_Response(0, id_registro, OwnerID, FinalSignature, ServerSignatureCertificate.getEncoded());

                                id_registro++;

                                salida.writeObject(mensaje_respuesta);
                                salida.flush();

                                System.out.println("\nSe ha realizado correctamente la operacion " + OperationMode + "\n");

                            }
                        
                        } else if (OperationMode.contains("RECUPERAR")) {

                            RecuperarDocumento_Request ClientMessage = (RecuperarDocumento_Request) datos.readObject();

                            //VALIDACION DEL ID REGISTRO
                            if (ClientMessage.getID_registro() > id_registro) {
                            
                                System.out.println("DOCUMENTO NO EXISTENTE.");
                                RecuperarDocumento_Response ResponseMessage = new RecuperarDocumento_Response(1);
                                salida.writeObject(ResponseMessage);
                                salida.flush();
                                return;

                            }

                            CertificateFactory CertificateFactoryInstance = CertificateFactory.getInstance("X.509");              
                            ByteArrayInputStream ClientAutenticationCertificateStream = new ByteArrayInputStream(ClientMessage.getClientAuthenticationCertificate());
                            X509Certificate ClientAutenticationCertificate = (X509Certificate)CertificateFactoryInstance.generateCertificate(ClientAutenticationCertificateStream);
                            
                            String DocName = ClientMessage.getID_registro() + "_" + ClientAutenticationCertificate.getSubjectX500Principal().getName() + ".sig.cif";
                            FileInputStream InputStreamDoc = null;

                            try {

                                InputStreamDoc = new FileInputStream(DocName);                       
                
                            } catch (FileNotFoundException e) {
                                
                                System.out.println("ACCESO NO PERMITIDO.");
                                System.out.println("(" + DocName + ")");
                                RecuperarDocumento_Response ResponseMessage = new RecuperarDocumento_Response(1);
                                salida.writeObject(ResponseMessage);
                                salida.flush();
                                return; 

                            }

                            byte[] DocRecovery = InputStreamDoc.readAllBytes();
                            InputStreamDoc.close();

                            //Total bytes = ? bytes (ciphered doc) + 189 bytes (doc signature) + 4 bytes (ID registro) + 23 bytes (timestamp) + 189 bytes (SigRD) + 
                            // + ? bytes (nombre doc) + 4 bytes (int longitud nombre doc) + ? bytes (AlgorithmParams) + 4 bytes (int lenght AlgorithmParams)
                            int RecoveredCipherParamsLenght =  ByteBuffer.wrap(Arrays.copyOfRange(DocRecovery, DocRecovery.length - 4, DocRecovery.length)).getInt();
                            int LenghtRecovered = DocRecovery.length - 4;
                            byte [] RecoveredCipherParams =  Arrays.copyOfRange(DocRecovery, LenghtRecovered - RecoveredCipherParamsLenght, LenghtRecovered);
                            LenghtRecovered -= RecoveredCipherParamsLenght;
                            int DocNameLenght = ByteBuffer.wrap(Arrays.copyOfRange(DocRecovery, LenghtRecovered - 4, LenghtRecovered)).getInt();
                            LenghtRecovered -= 4;
                            byte [] RecoveredDocName = Arrays.copyOfRange(DocRecovery, LenghtRecovered - DocNameLenght, LenghtRecovered);
                            LenghtRecovered -= DocNameLenght;
                            byte [] RecoveredRegisterSign = Arrays.copyOfRange(DocRecovery, LenghtRecovered - 189, LenghtRecovered);
                            LenghtRecovered -= 189;
                            //byte [] RecoveredTimeStamp = Arrays.copyOfRange(DocRecovery, LenghtRecovered - 23, LenghtRecovered);
                            LenghtRecovered -= 23;
                            byte [] RecoveredIDRegistro = Arrays.copyOfRange(DocRecovery, LenghtRecovered - 4, LenghtRecovered);
                            LenghtRecovered -= 4;
                            //byte [] RecoveredSignedDoc = Arrays.copyOfRange(DocRecovery, LenghtRecovered - 189, LenghtRecovered);
                            LenghtRecovered -= 189;
                            byte [] RecoveredCipheredDoc = Arrays.copyOfRange(DocRecovery, 0, LenghtRecovered);
                                                 

                            Object [] DecypheredDocObject = Cryptographic_Functions.Cipher_Decipher(false, true, ServerSecretKey, RecoveredCipheredDoc, "DES/CFB/PKCS5Padding", RecoveredCipherParams);
                            byte [] DecypheredDoc = (byte []) DecypheredDocObject[0];
   

                            //SE ENVIA LA RESPUESTA AL CLIENTE REALIZANDO DE NUEVO EL CIFRADO PGP
                            KeyGenerator PGPSymmetricKeyGenerator;
                            PGPSymmetricKeyGenerator = KeyGenerator.getInstance("AES");
                            PGPSymmetricKeyGenerator.init(192);
                            SecretKey PGPSymmetricKey = PGPSymmetricKeyGenerator.generateKey();

                            Object [] PGPEncryptedDocummentObject = Cryptographic_Functions.Cipher_Decipher(true, true, PGPSymmetricKey, DecypheredDoc, "AES/CBC/PKCS5Padding", null);
                            byte [] PGPEncryptedDocumment = (byte []) PGPEncryptedDocummentObject[0];
                            AlgorithmParameters PGPSymmetricAlgorithmParams = (AlgorithmParameters) PGPEncryptedDocummentObject[1];

                            java.security.PublicKey ClientAutenticationPublicKey = ClientAutenticationCertificate.getPublicKey();
                            Object [] PGPEncryptedSymmetricKeyObject = Cryptographic_Functions.Cipher_Decipher(true, false, ClientAutenticationPublicKey, PGPSymmetricKey.getEncoded(), "RSA/ECB/PKCS1Padding", null);
                            byte [] PGPEncryptedSymmetricKey = (byte []) PGPEncryptedSymmetricKeyObject[0];
                                
                            
                            KeyStore ServerKeyStore = KeyStore.getInstance("JCEKS");
                            ServerKeyStore.load(new FileInputStream(KeyStoreFile), StoresPassword);
                            X509Certificate ServerSignatureCertificate = (X509Certificate) ServerKeyStore.getCertificate("serverfirma");

                            RecuperarDocumento_Response ServerResopnse = new RecuperarDocumento_Response(0, ByteBuffer.wrap(RecoveredIDRegistro).getInt(), ClientAutenticationCertificate.getSubjectX500Principal(), new String(RecoveredDocName), (byte []) PGPSymmetricAlgorithmParams.getEncoded(), PGPEncryptedSymmetricKey, PGPEncryptedDocumment, RecoveredRegisterSign, ServerSignatureCertificate.getEncoded());
            
                            salida.writeObject(ServerResopnse);
                            salida.flush();

                            System.out.println("\nSe ha realizado correctamente la operacion " + OperationMode + "\n");


                        } else if (OperationMode.contains("SALIDA")){

                            System.out.println("\nEl cliente se ha desconectado.\n");
                            salida_bucle = true;
                            
                        } else {
                            System.out.println("\nModo de operacion inválido. - " + OperationMode + " -\n");
                        }
                    }

                } catch (IOException ie) {
                
                    ie.printStackTrace();
                    return;
                
                }

            } catch (Exception e) {
                e.printStackTrace();
                // write out error response
                out.println("HTTP/1.0 400 " + e.getMessage() + "\r\n");
                out.println("Content-Type: text/html\r\n\r\n");
                out.flush();
            }

        } catch (IOException ex) {
            // eat exception (could log error to log file, but
            // write out to stdout for now).
            System.out.println("error writing response: " + ex.getMessage());
            ex.printStackTrace();

        } finally {
            try {
                socket.close();
            } catch (IOException e) {
            }
        }
    }

    /********************************
     * Create a new thread to listen.
     ********************************/
    private void newListener() {
        (new Thread(this)).start();
    }

    /**********************************************
     * Returns the path to the file obtained from
     * parsing the HTML header.
     **********************************************/

    private static String getPath(BufferedReader in) throws IOException {
        String line = in.readLine();
        String path = "";

        // extract class from GET line
        if (line.startsWith("GET /")) {
            line = line.substring(5, line.length()-1).trim();
            int index = line.indexOf(' ');
            if (index != -1) {
                path = line.substring(0, index);
            }
        }

        // eat the rest of header
        do {
            line = in.readLine();
        } while ((line.length() != 0) &&
                 (line.charAt(0) != '\r') && (line.charAt(0) != '\n'));

        if (path.length() != 0) {
            return path;
        } else {
            throw new IOException("Malformed Header");
        }
    }




    /******************************************************
	* definirKeyStores()
	*****************************************************/
    private static String KeyStoreFile   = CertStoresPath + "ServerKeystore.jce";
    private static String TrustStoreFile = CertStoresPath + "ServerTruststore.jce";
    private static char[] StoresPassword = "seg2223".toCharArray();

    private static void DefinedKeyStores() {

		//KeyStore		
		System.setProperty("javax.net.ssl.keyStore", CertStoresPath + "ServerKeystore.jce");
		System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.keyStorePassword", "seg2223");

		//TrustStore
		System.setProperty("javax.net.ssl.trustStore", CertStoresPath + "ServerTrustStorer.jce");		
		System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.trustStorePassword", "seg2223");

	}

}
