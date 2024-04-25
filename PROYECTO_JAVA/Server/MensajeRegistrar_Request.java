import java.io.Serializable;

public class MensajeRegistrar_Request implements Serializable {

    private static final long serialVersionUID = -6392106198310247082L;

    private String nombreDoc;

    private byte[] documentoCifrado;
    private byte[] claveSimetricaCifrada;
    private byte[] parametrosCifrado;
    private byte[] firmaDocumento;
    private byte[] certificadoFirmaC;
    private byte[] certificadoCifradoC;

    public MensajeRegistrar_Request(String nombre, byte[] doccif, byte[] clavesim, byte[] paramcif,  byte[] firma, byte[] certfirma, byte[] certcif){
    
        this.nombreDoc = nombre;
        this.documentoCifrado = doccif;
        this.claveSimetricaCifrada = clavesim;
        this.parametrosCifrado = paramcif;
        this.firmaDocumento = firma;
        this.certificadoFirmaC = certfirma;
        this.certificadoCifradoC = certcif;
    
    }

    public String getNombreDoc() {
    
        return this.nombreDoc;
    
    }

    public byte[] getDocumentoCifrado() {
    
        return this.documentoCifrado;
    
    }

    public byte[] getClaveSimetricaCifrada() {
    
        return this.claveSimetricaCifrada;
    
    }
 
    public byte[] getParametrosCifrado() {

        return this.parametrosCifrado;
        
    }    

    public byte[] getFirmaDocumento() {
    
        return this.firmaDocumento;
    
    }

    public byte[] getCertificadoCifradoC() {
    
        return this.certificadoCifradoC;
    
    }

    public byte[] getCertificadoFirmaC() {

        return this.certificadoFirmaC;
    
    }   
}