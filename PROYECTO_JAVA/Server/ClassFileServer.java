import java.io.*;
import java.net.*;
import java.security.KeyStore;
import java.security.cert.CertPathBuilder;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509CertSelector;
import java.util.EnumSet;

import javax.net.*;
import javax.net.ssl.*;

/*****************************************************************
 * ClassFileServer.java -- a simple file server that can server
 * Http get request in both clear and secure channel
 *
 * The ClassFileServer implements a ClassServer that
 * reads files from the file system. See the
 * doc for the "Main" method for how to run this
 * server.
 ****************************************************************/

public class ClassFileServer extends ClassServer {

    private String docroot;

    private static int DefaultServerPort = 9001;
	private static String CertStoresPath = "C:/Users/omard/Desktop/Teleco/CUATRI_1/SEG/SEG_B/";

	private static TrustManagerSeg tManager;

    /****************************************************************
     * Constructs a ClassFileServer.
     * @param path the path where the server locates files
    ****************************************************************/
    public ClassFileServer(ServerSocket ss, String docroot) throws IOException {
		super(ss);
		this.docroot = docroot;
    }

    /**************************************************************
     * Returns an array of bytes containing the bytes for
     * the file represented by the argument <b>path</b>.
     *
     * @return the bytes for the file
     * @exception FileNotFoundException if the file corresponding
     * to <b>path</b> could not be loaded.
    **************************************************************/
    
	public byte[] getBytes(String path) throws IOException {
		
		System.out.println("reading: " + path);	
		
		File f = new File(docroot + File.separator + path);
		int length = (int)(f.length());
		
		if (length == 0) {
	    
			throw new IOException("File length is zero: " + path);
		
		} else {
	    
			FileInputStream fin = new FileInputStream(f);
	    	DataInputStream in = new DataInputStream(fin);

	    	byte[] bytecodes = new byte[length];
	    	in.readFully(bytecodes);
	    
			return bytecodes;
		}
    }

    /*****************************************************
     * Main method to create the class server that reads
     * files. This takes two command line arguments, the
     * port on which the server accepts requests and the
     * root of the path. To start up the server: <br><br>
     *
     * <code>   java ClassFileServer <port> <path>
     * </code><br><br>
     *
     * <code>   new ClassFileServer(port, docroot);
     * </code>
    ******************************************************/
    
    public static void main(String args[]) {
   	
		String[] cipherSuites = null;
        
		System.out.println("USAGE: java ClassFileServer port docroot [TLS [true]]");
		System.out.println("");
		System.out.println("If the third argument is TLS, it will start as\n" +
	    	"a TLS/SSL file server, otherwise, it will be\n" +
	    	"an ordinary file server. \n" +
	    	"If the fourth argument is true,it will require\n" +
	    	"client authentication as well.");

		int port = DefaultServerPort;
		String docroot = "";

		//Definir valores para los almacenes necesarios
	
		DefinedKeyStores();
	
		//Definir las variables para establecer OCSP stapling
		definirRevocacionOCSPStapling();
	
		//Chequear argumentos
		if (args.length >= 1) {
	    	port = Integer.parseInt(args[0]);
		}

		if (args.length >= 2) {
	    	docroot = args[1];
		}
	
		String type = "PlainSocket";
		if (args.length >= 3) {
	    	type = args[2];
		}
	
		try {

	    	ServerSocketFactory ssf = ClassFileServer.getServerSocketFactory(type);
	    	ServerSocket ss = ssf.createServerSocket(port);
	    
	    	// Ver los protocolos
    		System.out.println ("*****************************************************");
    		System.out.println ("*  Protocolos soportados en Servidor                 ");
    		System.out.println ("*****************************************************");

	 		String[] protocols = ((SSLServerSocket)ss).getEnabledProtocols();
	 		
			for (int i=0; i<protocols.length; i++) 
	    		System.out.println (protocols[i]);

    		System.out.println ("*****************************************************");
    		System.out.println ("*    Protocolo forzados                              ");
    		System.out.println ("*****************************************************");
	 	
	 		String[] protocolsNew = {"TLSv1.3"};
	 	
	 		((SSLServerSocket)ss).setEnabledProtocols(protocolsNew);
	 	
	 		//volvemos a mostrarlos
	 		protocols = ((SSLServerSocket)ss).getEnabledProtocols();

	 		for (int i=0; i<protocols.length; i++)     	
				System.out.println (protocols[i]);	    
    	
	
	    	if (args.length >= 4 && args[3].equals("true")) {
	    
	    		System.out.println ("*****************************************************");
	    		System.out.println ("*  Server inicializado CON Autenticacion de cliente  ");
	    		System.out.println ("*****************************************************");

	    		// Ver Suites disponibles en Servidor
	    	
		    	System.out.println ("*****************************************************");
	    		System.out.println ("*         CypherSuites Disponibles en SERVIDOR       ");
	    		System.out.println ("*****************************************************");
	    	
			 	cipherSuites = ((SSLServerSocket)ss).getSupportedCipherSuites();
		
				for (int i=0; i<cipherSuites.length; i++) 
			    	System.out.println (i + "--" + cipherSuites[i]);	    
	    	
		 		//Definir suites Habilitadas en server 	
		 		((SSLServerSocket)ss).setNeedClientAuth(true);
		 	
	        	String[] cipherSuitesHabilitadas = {"TLS_RSA_WITH_NULL_SHA256",
	        		                              "TLS_ECDHE_RSA_WITH_NULL_SHA",
	        		                               //TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	        		                               //"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	        		                              };

	        	if (false) // cambiar a true para cambiarlas
	        		((SSLServerSocket)ss).setEnabledCipherSuites(cipherSuitesHabilitadas);
	        
	    		System.out.println ("*****************************************************");
	    		System.out.println ("*         CypherSuites Habilitadas en SERVIDOR       ");
	    		System.out.println ("*****************************************************");
	    
		 		cipherSuites = ((SSLServerSocket)ss).getEnabledCipherSuites();
		 		
				for (int i=0; i<cipherSuites.length; i++) 
		    		System.out.println (i + "--" + cipherSuites[i]);	    
	    	}
	    
	    	new ClassFileServer(ss, docroot);

		} catch (IOException e) {
		    System.out.println("Unable to start ClassServer: " + e.getMessage());
	    	e.printStackTrace();
		}
    }

    private static ServerSocketFactory getServerSocketFactory(String type) {
	
    	if (type.equals("TLS")) {
    	
	    	SSLServerSocketFactory ssf = null;

	    	try {
	    	
	    		definirRevocacionOCSPStapling();
	    	
  				/********************************************************************************
				* Construir un contexto, pasandole el KeyManager y y TrustManager 
				* Al TrustManager se le incorpora el chequeo de certificados revocados por Ocsp. 
				*   
				* NOTA: Esto seria necesario para la verificacion de no-revocacion OCSP
				* del certificado del cliente
				*   
				********************************************************************************/
	    		// set up key manager to do server authentication

				char[] passphrase = "seg2223".toCharArray();
			
				// Trust manager.
			 
				// 1. Crear PKIXRevocationChecker
				CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX");
				PKIXRevocationChecker rc = (PKIXRevocationChecker) cpb.getRevocationChecker();
				rc.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));
				rc.setOcspResponder(new URI("http://127.0.0.1:9080"));  // Aqui poner la ip y puerto donde se haya lanzado el OCSP Responder


				// 2. Crear el truststore 		
				KeyStore ts = KeyStore.getInstance("JCEKS");
				ts.load(new FileInputStream(CertStoresPath + "ServerTruststore.jce"), passphrase);
			
				// 3. Crear los parametros PKIX y el PKIXRevocationChecker
				PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(ts, new X509CertSelector());
				pkixParams.addCertPathChecker(rc);
				pkixParams.setRevocationEnabled(true); 
			
				TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
				tmf.init(new CertPathTrustManagerParameters(pkixParams));

				X509TrustManager mytm = null;
				for (TrustManager tm : tmf.getTrustManagers()) {
					if (tm instanceof X509TrustManager) {
						mytm = (X509TrustManager) tm;
						break;
					}
				}
				tManager = new TrustManagerSeg(mytm, CertStoresPath + "ServerTruststore.jce");
			
	    		// Set up key manager to do server authentication
				KeyManagerFactory kmf;
				KeyStore ks;
	
				// Key manager 
				kmf = KeyManagerFactory.getInstance("SunX509");
				ks = KeyStore.getInstance("JCEKS");	
				ks.load(new FileInputStream(CertStoresPath + "ServerKeystore.jce"), passphrase);
				kmf.init(ks, passphrase);
		
				// Crear el contexto
				SSLContext ctx;
				ctx = SSLContext.getInstance("TLS");		
				ctx.init(kmf.getKeyManagers(),  
				tmf.getTrustManagers(), //solo si se hace el OCSP del certificado del cliente
				null);
			
				ssf = ctx.getServerSocketFactory();
				return ssf;
			
	    	} catch (Exception e) {
				e.printStackTrace();
		    }

		} else {
	
			return ServerSocketFactory.getDefault();
	
		}
	
		return null;
    }



    private static void DefinedKeyStores() {

		//KeyStore		
		System.setProperty("javax.net.ssl.keyStore", CertStoresPath + "ServerKeystore.jce");
		System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.keyStorePassword", "seg2223");

		//TrustStore
		System.setProperty("javax.net.ssl.trustStore", CertStoresPath + "ServerTruststore.jce");		
		System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.trustStorePassword", "seg2223");

	}



	private static void definirRevocacionOCSPStapling()	{

    	/*******************************************************
    	* Metodo 2: Con URL en el codigo java del server  (aqui)
    	*******************************************************/
    
    		System.setProperty("jdk.tls.server.enableStatusRequestExtension", "true");
	  		System.setProperty("jdk.tls.stapling.responderOverride","true");
			System.setProperty("jdk.tls.stapling.responderURI", "http://localhost:9080");		
			System.setProperty("jdk.tls.stapling.ignoreExtensions", "true");
	}
}