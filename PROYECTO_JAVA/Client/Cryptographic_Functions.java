import java.io.*;

import java.security.*;
import java.security.cert.*;

import javax.crypto.*;

public class Cryptographic_Functions {

    //DEVOLVERA UN ARRAY DE BYTES CON EL DOCUMENTO CIFRADO/DESCIFRADO SI NO HAN OCURRIDO ERRORES.
    static Object[] Cipher_Decipher (boolean Encrypting, boolean Symmetric, Key CipherKey, byte [] InDoc, String CipherMode, byte[] CipherParameters) {

        Object [] OutDocAndParams = new Object [2];
        byte[] OutDoc = null;
        AlgorithmParameters OutDocParams = null;

        //Indica un 0 en los mensajes de error si ocurrio durante el cifrado, 1 durante el descifrado
        int FunctionMode = 0;

        try {

            Cipher CipherInstance = Cipher.getInstance(CipherMode);

            if (Encrypting) {

                CipherInstance.init(Cipher.ENCRYPT_MODE, CipherKey);

            } else {

                if (Symmetric) {

                    AlgorithmParameters SymmetricCipherParameters = AlgorithmParameters.getInstance(CipherKey.getAlgorithm());
                    SymmetricCipherParameters.init(CipherParameters);
                    CipherInstance.init(Cipher.DECRYPT_MODE, CipherKey, SymmetricCipherParameters);
 
                } else {

                    CipherInstance.init(Cipher.DECRYPT_MODE, CipherKey);

                }
    
                FunctionMode = 1;
    
            }

            int BlockLenght;
            byte [] InBlock = new byte [1024];
            byte [] OutBlock = null;

            ByteArrayInputStream InDocStream = new ByteArrayInputStream(InDoc);
            ByteArrayOutputStream OutDocStream = new ByteArrayOutputStream();

            while ((BlockLenght = InDocStream.read(InBlock)) > 0) {

                OutBlock = CipherInstance.update(InBlock, 0, BlockLenght);
                OutDocStream.write(OutBlock);

            }

            OutBlock = CipherInstance.doFinal();
            OutDocStream.write(OutBlock);

            OutDoc = OutDocStream.toByteArray();

            if (Symmetric&&Encrypting) {

                OutDocParams = CipherInstance.getParameters();
    
            }



        } catch (InvalidAlgorithmParameterException e) {
            System.out.println("\nError en el cifrado/descifrado (" + FunctionMode + "): No se han podido obtener los parametros del algoritmo.");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("\nError en el cifrado/descifrado (" + FunctionMode + "): Algoritmo desconocido.");
        } catch (NoSuchPaddingException e) {
            System.out.println("\nError en el cifrado/descifrado (" + FunctionMode + "): Modo de operación desconocido.");
        } catch (InvalidKeyException e) {
            System.out.println("\nError en el cifrado/descifrado (" + FunctionMode + "): La clave introducida no es válida.");
        } catch (IOException e) {           
            System.out.println("\nError en el cifrado/descifrado (" + FunctionMode + "): No se ha podido leer el documento a cifrar.");
        }  catch (IllegalBlockSizeException e) {
            System.out.println("\nError en el cifrado/descifrado (" + FunctionMode + "): Longitud de los bloques de cifrado sobrepasada.");
        } catch (BadPaddingException e) {
            System.out.println("\nError en el cifrado/descifrado (" + FunctionMode + "): Ha habido un error con el modo de operación.");
        } 

        OutDocAndParams[0] = OutDoc;
        OutDocAndParams[1] = OutDocParams;
        return OutDocAndParams;
    }



    //FUNCION PARA LA FIRMA DE UN DOCUMENTO. DEVOLVERA UN ARRAY DE BYTES CON LA FIRMA SI NO HAN OCURRIDO ERRORES.
    static byte[] Sign_Document(PrivateKey SignaturePrivateKey, byte [] Doc, byte [] SignerCertificateRaw) {
        
        byte [] SignedDocument = null;

        ByteArrayInputStream SignerCertificateStream = new ByteArrayInputStream(SignerCertificateRaw);

        try {

            CertificateFactory certificateFactoryInstance = CertificateFactory.getInstance("X.509");
            X509Certificate SignerCertificate = (X509Certificate) certificateFactoryInstance.generateCertificate(SignerCertificateStream);

            //Se usará un objeto de la clase Signature para realizar la firma, introduciendo el algoritmo con el que se realizará
            Signature signer = Signature.getInstance(SignerCertificate.getSigAlgName());

            //Inicializamos el objeto con la clave privada del firmante
            signer.initSign(SignaturePrivateKey);

            byte [] Block = new byte [1024];
            int BlockLenght;

            ByteArrayInputStream DocStream = new ByteArrayInputStream(Doc);

            while ((BlockLenght = DocStream.read(Block)) > 0) {

                signer.update(Block, 0, BlockLenght);

            }

            SignedDocument = signer.sign();

        } catch (CertificateException e) {
            System.out.println("\nError en la firma: No se ha podido acceder al certificado de firma.");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("\nError en la firma: Algoritmo desconocido.");
        } catch (InvalidKeyException e) {
            System.out.println("\nError en la firma: Clave de firma no válida.");
        } catch (SignatureException e) {
            System.out.println("\nError en la firma: No ha podido firmarse correctamente.");
        } catch (IOException e) {
            System.out.println("\nError en la firma: El documento a firmar no se ha podido leer correctamente.");
        } 

        return SignedDocument;
    }    
    
    
    //FUNCION PARA VERIFICACION DE UNA FIRMA. DEVOLVERA UN BOOLEANO CON EL RESULTADO DE LA OPERACION.
    static boolean SignatureVerification(byte [] SignedDocument, byte[] Doc, byte [] SignerCertificateRaw) {

        boolean Verified = false;

        ByteArrayInputStream SignerCertificateStream = new ByteArrayInputStream(SignerCertificateRaw);

        try {
            
            CertificateFactory certificateFactoryInstance = CertificateFactory.getInstance("X.509");
            X509Certificate SignerCertificate = (X509Certificate) certificateFactoryInstance.generateCertificate(SignerCertificateStream);

            Signature verifier = Signature.getInstance(SignerCertificate.getSigAlgName());

            verifier.initVerify(SignerCertificate.getPublicKey());

            ByteArrayInputStream DocStream = new ByteArrayInputStream(Doc);

            int BlockLenght;
            byte [] Block = new byte[1024];

            while ((BlockLenght = DocStream.read(Block)) > 0) {
            
                verifier.update(Block, 0, BlockLenght);
            
            }

            Verified = verifier.verify(SignedDocument);
        
        } catch (CertificateException e) {
            System.out.println("\nError en la verificacion de la firma: El formato del certificado no es válido.");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error en la verificacion de la firma: El algorimo provisto por el certificado no es válido.");
        } catch (InvalidKeyException e) {
            System.out.println("Error en la verificacion de la firma: La clave pública no es válida.");
        } catch (IOException e) {
            System.out.println("Error en la verificacion de la firma: Error en la lectura del documento.");
        } catch (SignatureException e) {
            System.out.println("Error en la verificacion de la firma: No ha podido verificarse correctamente.");
        }
        
        return Verified;
    }
}