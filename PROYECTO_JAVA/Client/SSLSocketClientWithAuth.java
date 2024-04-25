import java.io.*;
import java.net.URI;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;
import java.util.Scanner;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;



public class SSLSocketClientWithAuth {

	public static Scanner teclado = new Scanner(System.in);

	private static String raizAlmacenes = "C:/Users/omard/Desktop/Teleco/CUATRI_1/SEG/SEG_B/";

	private static TrustManagerSeg tManager;

	public static void main(String[] args) throws Exception {

		String host = null;
		String path = null;
		int    port = 9001;
		char[] contrasenhaAlmacen = "seg2223".toCharArray();
		
		String[] cipherSuites = null;

		for (int i = 0; i < args.length; i++)
			System.out.println(args[i]);

		if (args.length < 3) {
			System.out.println("USAGE: java SSLSocketClientWithClientAuth host port requestedfilepath");
			System.exit(-1);
		}

		try {
			host = args[0];
			port = Integer.parseInt(args[1]);
			path = args[2];
		} catch (IllegalArgumentException e) {
			System.out.println("USAGE: java SSLSocketClientWithClientAuth host port requestedfilepath");
			System.exit(-1);
		}

		definirKeyStores();
		//definirRevocacionOCSPStapling();
		//definirRevocacionOCSP();

		SSLSocketFactory factory = null;

		try {

			/*****************************************************************************
			 * Crear un key manager para la autentication del cliente. 
			 * Usar el TrustStore y secureRandom por defecto.
			 ****************************************************************************/
			SSLContext ctx;
			KeyManagerFactory kmf;
			KeyStore ks;

			try {

				/********************************************
				* Se inicializa el contexto pasandole:
				* 
				* - el/los KeyManagers creado/s. 
				* - el TrustManager por defecto (null). 
				* - el SecureRamdom por defecto (null).
				********************************************/
            
				/*  --- Trust manager.
				// 1. Crear PKIXRevocationChecker
				CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX");
				PKIXRevocationChecker rc = (PKIXRevocationChecker) cpb.getRevocationChecker();
				rc.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));
				rc.setOcspResponder(new URI("http://localhost:9080")); 

				// 2. Crear el truststore 
				KeyStore ClientTruststore = KeyStore.getInstance("JCEKS");
				ClientTruststore.load(new FileInputStream(raizAlmacenes + "ClientTruststore.jce"), contrasenhaAlmacen);

				// 3. Crear los parametros PKIX y el PKIXRevocationChecker
				PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(ClientTruststore, new X509CertSelector());
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
				
				tManager = new TrustManagerSeg(mytm, raizAlmacenes + "ClientTruststore.jce");
				*/

				/***************************************************************************
				* Definir el/los KeyManager.
				*
				* Ahora son necesarios ya que el cliente necesita autenticarse y por tanto
				* tenemos que informar al SSL de donde tomar las credenciales del cliente.
				***************************************************************************/
				kmf = KeyManagerFactory.getInstance("SunX509");
				ks = KeyStore.getInstance("JCEKS");
				ks.load(new FileInputStream(ficheroKeyStore), contrasenhaAlmacen);
				kmf.init(ks, contrasenhaAlmacen);
				
				// Crear el contexto
				ctx = SSLContext.getInstance("TLS");
				ctx.init(kmf.getKeyManagers(), null, null);
				
				// Asignamos un socket al contexto.
				factory = ctx.getSocketFactory();

				/*********************************************************************
				* Suites del contexto
				*********************************************************************/
				System.out.println("******** CypherSuites Disponibles **********");
				cipherSuites = factory.getSupportedCipherSuites();
				for (int i = 0; i < cipherSuites.length; i++)
					System.out.println(cipherSuites[i]);

		
				/*********************************************************************
				* Suites habilitadas por defecto
				*********************************************************************/
				System.out.println("******* CypherSuites Habilitadas por defecto **********");

				String[] cipherSuitesDef = factory.getDefaultCipherSuites();
				for (int i = 0; i < cipherSuitesDef.length; i++)
					System.out.println(cipherSuitesDef[i]);

			} catch (Exception e) {
				throw new IOException(e.getMessage());
			}

			SSLSocket socket = (SSLSocket) factory.createSocket(host, port);

			/*
			// Ver los protocolos
	  
			System.out.println ("*****************************************************");
			System.out.println ("*  Protocolos soportados en Cliente                 ");
			System.out.println ("*****************************************************");
	 
		    String[] protocols = socket.getEnabledProtocols();
		    
			for (int i=0; i<protocols.length; i++) 
				System.out.println (protocols[i]);	    
			   
			System.out.println ("*****************************************************");
			System.out.println ("*    Protocolo forzado                               ");
			System.out.println ("*****************************************************");
			  
		    String[] protocolsNew = {"TLSv1.3"};	  
		 
		    socket.setEnabledProtocols(protocolsNew);
			*/
	 
	 	    System.out.println ("*****************************************************");
	  	    System.out.println ("*         CypherSuites  Disponibles (Factory)        ");
		    System.out.println ("*****************************************************");

			String [] cipherSuitesDisponibles = factory.getSupportedCipherSuites();
			for (int i=0; i<cipherSuitesDisponibles.length; i++) 
				 System.out.println (cipherSuitesDisponibles[i]);

			String[] cipherSuitesHabilitadas = { "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_AES_256_GCM_SHA384" };

			System.out.println(cipherSuitesHabilitadas[0]);

			socket.setEnabledCipherSuites(cipherSuitesHabilitadas);

			System.out.println("****** CypherSuites Habilitadas  **********");

			String[] cipherSuitesHabilSocket = socket.getEnabledCipherSuites();
			for (int i = 0; i < cipherSuitesHabilSocket.length; i++)
				System.out.println(cipherSuitesHabilSocket[i]);

			System.out.println("\n*************************************************************");
			System.out.println("  Comienzo SSL Handshake -- Cliente y Servidor Autenticados     ");
			System.out.println("*************************************************************");

			socket.startHandshake();

			System.out.println("\n*************************************************************");
			System.out.println("      Fin OK   SSL Handshake");
			System.out.println("*************************************************************");

			
			OutputStream salida = socket.getOutputStream();
			PrintWriter cabecera = new PrintWriter(new BufferedWriter(new OutputStreamWriter(salida)));
			ObjectOutputStream datos = new ObjectOutputStream(salida);


			InputStream entrada = socket.getInputStream();
			BufferedReader flujo_cabecera = new BufferedReader(new InputStreamReader(entrada));
			ObjectInputStream flujo_datos = new ObjectInputStream(entrada);

/*
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate cert1 = (X509Certificate) socket.getSession().getPeerCertificates()[0];

			
			//Guardamos en el truststore el certificado del servidor obtenido durante el handshake
			KeyStore ClientTruststore = KeyStore.getInstance("JCEKS");
			ClientTruststore.load(new FileInputStream(raizAlmacenes + "ClientTruststore.jce"), contrasenhaAlmacen);

			ClientTruststore.setCertificateEntry("servertls", cert1);
			ClientTruststore.store(new FileOutputStream(raizAlmacenes + "ClientTruststore.jce"), contrasenhaAlmacen);

			                    

			X509Certificate[] chain = new X509Certificate[1];
			chain[0] = (X509Certificate) ClientTruststore.load(new FileInputStr"));
			X509Certificate[] new_chain = new X509Certificate[2];
			System.arraycopy(chain, 0, new_chain, 0, chain.length);
			new_chain[chain.length] = (X509Certificate) socket.getSession().getPeerCertificates()[1];
			ClientTruststore.setKeyEntry("servertls", (Key) socket.getSession().getPeerCertificates()[0].getPublicKey(), contrasenhaAlmacen, new_chain);
			ClientTruststore.store(new FileOutputStream(raizAlmacenes + "ClientTruststore.jce"), contrasenhaAlmacen);
*/
			boolean salida_bucle = false;

			while(!salida_bucle) {

				char seleccion = menu();

				switch(seleccion) {
					case '1': {

						System.out.println("REGISTRAR DOCUMENTO");

						MensajeRegistrar_Request mensajeRegistro = Registrar.Request();

						//enviar cabecera
						cabecera.println("REGISTRAR");
						cabecera.flush();

						//enviar datos
						datos.writeObject(mensajeRegistro);
						datos.flush();

						MensajeRegistrar_Response respuesta = (MensajeRegistrar_Response) flujo_datos.readObject();

						Registrar.Response(respuesta);

						break;

					}
					case '2': {
					
						System.out.println("RECUPERAR DOCUMENTO");

						RecuperarDocumento_Request mensajeRecuperar = Recuperar.Request(); 

						//enviar cabecera
						cabecera.println("RECUPERAR");
						cabecera.flush();

						//enviar datos
						datos.writeObject(mensajeRecuperar);
						datos.flush();

						//Leer respuesta
						RecuperarDocumento_Response ServerResponse_Recovery = (RecuperarDocumento_Response) flujo_datos.readObject();
						Recuperar.Response(ServerResponse_Recovery);

						break;

					}
					case '3': 
						salida_bucle = true;
						cabecera.println("SALIDA");
						cabecera.flush();
						break;

					default:
						System.out.println("Opcion invalida.\n");
						break;
				}
			}

		} catch (Exception e) {
			e.printStackTrace();;
		}
	}


	//Muestra el menu por pantalla y lee la opcion introducida
	static char menu() {

		char seleccion;

		System.out.println("Elige la opcion deseada: \n");
		System.out.println(" - 1) Registrar un documento. \n");
		System.out.println(" - 2) Recuperar un documento.\n");
		System.out.println(" - 3) Salir.");

		seleccion = teclado.nextLine().trim().charAt(0);

		return seleccion;

	}

	/******************************************************
	 * definirKeyStores()
	 *****************************************************/
    private static String ficheroKeyStore   = raizAlmacenes + "ClientKeystore.jce";
    private static String ficheroTrustStore = raizAlmacenes + "ClientTruststore.jce";

	private static void definirKeyStores() {

		// KeyStore
		System.setProperty("javax.net.ssl.keyStore", ficheroKeyStore);
		System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.keyStorePassword", "seg2223");

		// TrustStore	
		System.setProperty("javax.net.ssl.trustStore", ficheroTrustStore);
		System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.trustStorePassword", "seg2223");

	}

	/*
	private static void definirRevocacionOCSP() {

		//Almacen de claves
		System.setProperty("com.sun.net.ssl.checkRevocation", "true");
		System.setProperty("ocsp.enable", "true");

	}
    

    private static void definirRevocacionOCSPStapling() {

		//Almacen de claves	
		System.setProperty("jdk.tls.client.enableStatusRequestExtension", "true");
		System.setProperty("com.sun.net.ssl.checkRevocation", "true");
		System.setProperty("ocsp.enable", "true");

	}
	*/

}