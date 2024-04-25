import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Scanner;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

public class TrustManagerSeg extends X509ExtendedTrustManager {
    final X509TrustManager client_TrustManager;
    private String trusts;

    public TrustManagerSeg(X509TrustManager client_TrustManager, String trusts) {
        this.client_TrustManager = client_TrustManager;
        this.trusts = trusts;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
        // TODO Auto-generated method stub

    }

    @Override
    public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
        try {
            client_TrustManager.checkServerTrusted(arg0, arg1);
        } catch (Exception e) {
            try {
                System.out
                        .print("Las credenciales del servidor no son confiables. Desea aceptarlas igualmente? (s/n): ");
                Scanner sc = new Scanner(System.in);
                String cadena = sc.nextLine().trim();
                if (cadena.equals("n")) {
                    System.out.println("Comunicacion abortada.");
                    System.exit(-1);
                } else {
                    System.out.print("Introduzca la contrasenha del truststore: ");
                    String pswd = sc.nextLine().trim();
                    KeyStore tStore;
                    tStore = KeyStore.getInstance("JCEKS");
                    tStore.load(new FileInputStream(trusts), pswd.toCharArray());
                    System.out.print("Introduzca el alias: ");
                    String alias = sc.nextLine().trim();
                    tStore.setCertificateEntry(alias, arg0[0]);
                    tStore.store(new FileOutputStream(trusts), pswd.toCharArray());
                }
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }

    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] arg0, String arg1, Socket arg2) throws CertificateException {
        // TODO Auto-generated method stub

    }

    @Override
    public void checkClientTrusted(X509Certificate[] arg0, String arg1, SSLEngine arg2) throws CertificateException {
        // TODO Auto-generated method stub

    }

    @Override
    public void checkServerTrusted(X509Certificate[] arg0, String arg1, Socket arg2) throws CertificateException {
        // TODO Auto-generated method stub

    }

    @Override
    public void checkServerTrusted(X509Certificate[] arg0, String arg1, SSLEngine arg2) throws CertificateException {
        // TODO Auto-generated method stub

    }

}