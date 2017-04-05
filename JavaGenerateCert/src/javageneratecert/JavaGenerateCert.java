/*
 * FOOD Chain Project
 *  
 * This project is created by Loo Cheah Hong
 * 2017 (c) Loo Cheah Hong
 */

package javageneratecert;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;
	
import javax.xml.bind.DatatypeConverter;
import java.io.StringWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.ProtectionParameter;
import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import javax.crypto.Cipher;
import org.json.simple.JSONObject;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

/**
 *
 * @author CheahHong
 */
public class JavaGenerateCert {
    
    private static final int keysize = 1024;
    private static final String commonName = "www.foodchain.com";
    private static final String organizationalUnit = "IT";
    private static final String organization = "Techies";
    private static final String city = "Kuching";
    private static final String state = "Sarawak";
    private static final String country = "Malaysia";
    private static final long validity = 1096; // 3 years
    private static final String alias = "tomcat";
    private static final char[] keyPass = "changeit".toCharArray();
    
    private static final String keystoreFilePath = "Btu\\.keystore";
    private static final String certFilePath = "Btu\\Btu.pem";
    private static final String locationFilePath = "Btu\\Btu.txt";
    
    private static PrivateKey privKey;
    private static KeyStore keyStore;
    private static X509Certificate cert;
    
    final protected static String cipherAlgorithm = "RSA/ECB/PKCS1Padding";
    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
    
    /**
    * @param args the command line arguments
    */
    @SuppressWarnings("restriction")
    public static void main(String[] args) throws Exception{
        
        // check if keystore and cert exist
        // if not generate
        if(areKeyStorePresent()) { 
            System.out.println("Keystore file & Certificate exist\n");
            loadKeyStoreAndGetPrivKey();
        }else{
            System.out.println("Created Keystore file & Certificate PEM file\n");
            generateKeyStoreAndCertFile();
        }
        
        System.out.println("Private Key: "+privKey);
        System.out.println("KeyStore: "+keyStore+"\n");
        
        //open a server socket to listen to GET requests
        ServerSocket server = new ServerSocket(7080);
        int counter=0;
        System.out.println("Listening for connection on port 7080 ....\n");
        while (true) {
            try (Socket socket = server.accept()) {
                JSONObject jsonObjForOriData = new JSONObject();
                JSONObject jsonObjForOriAndHashedData = new JSONObject();
                
                //request counter
                System.out.println("Server received request: "+counter);
                counter++;
                
                //read location data from file
                String locationData = readFile(locationFilePath,StandardCharsets.UTF_8);
                
                //put the location data and currenDateTime in json object
                jsonObjForOriData.put("location", locationData);
                jsonObjForOriData.put("currentDateTime",getCurrentDateTime().toString());
                System.out.println("Original Json Data: "+jsonObjForOriData.toString());
                
                //hash the json obj
                String hashedJson = hashStringWithSHA(jsonObjForOriData.toString());
                System.out.println("Original Hash: "+hashedJson);
                
                //encrypt the hash using privateKey
                byte[] encryptedHash = encrypt(hashedJson ,privKey);
                
                //convert bytes to hex string
                String encodedEncryptedHash = bytesToHex(encryptedHash);
                System.out.println("Encrypted hash: "+encodedEncryptedHash);
                
                //split hex string into equal parts
                int splitLength = whereToSplit(encodedEncryptedHash.length());
                String[] hashArray = splitEqually(encodedEncryptedHash,splitLength);
                
                //put encoded encrypted hash parts and original json data in json Obj
                for(int i=0;i<hashArray.length;i++){
                    jsonObjForOriAndHashedData.put("encryptedHash"+(i+1),hashArray[i]);
                }
                jsonObjForOriAndHashedData.put("unhashedData",jsonObjForOriData);
                System.out.println("Response: "+jsonObjForOriAndHashedData.toString());
                
                //Output the response string
                String httpResponse = "HTTP/1.1 200 OK\r\n\r\n" + jsonObjForOriAndHashedData.toString();
                socket.getOutputStream().write(httpResponse.getBytes("UTF-8"));
            }
        }
    }
    
   /**
   * The method encodes the X509certificate to string
   * 
   * @return encoded X509certificate in string
   */
    public static String certToString(X509Certificate cert){
        StringWriter sw = new StringWriter();
        try {
            sw.write("-----BEGIN CERTIFICATE-----\n");
            sw.write(DatatypeConverter.printBase64Binary(cert.getEncoded()).replaceAll("(.{64})", "$1\n"));
            sw.write("\n-----END CERTIFICATE-----\n");
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
        return sw.toString();
    }
    
   /**
   * The method checks if the key store file has been generated.
   * 
   * @return flag indicating if the key store file was generated.
   */
    public static boolean areKeyStorePresent() {
        
      File keystoreFile = new File(keystoreFilePath);

      if(keystoreFile.exists() && !keystoreFile.isDirectory()) {
        return true;
      }
      return false;
    }
    
   /**
   * Encrypt string using private key
   * 
   * @param text
   *          : string
   * @param key
   *          :The private key
   * @return Encrypted text
   * @throws java.lang.Exception
   */
    public static byte[] encrypt(String text, Key key) {
      byte[] cipherText = null;
      try {
        // get an RSA cipher object and print the provider
        final Cipher cipher = Cipher.getInstance(cipherAlgorithm);
        
        // encrypt the plain text using the private key
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipherText = cipher.doFinal(text.getBytes());
      } catch (Exception e) {
        e.printStackTrace();
      }
      return cipherText;
   }
    
   /**
   * Read all text from file
   * 
   * @param path
   *          :path to the text file
   * @param encoding 
   *          :The type of Charset encoding
   * @return plain text
   * @throws java.io.IOException
   */
    public static String readFile(String path, Charset encoding) throws IOException 
    {
       byte[] encoded = Files.readAllBytes(Paths.get(path));
       return new String(encoded, encoding);
    }
    
   /**
   * Get current date and time
   */
    public static String getCurrentDateTime()
    {
        DateFormat dateFormat = new SimpleDateFormat("EEE, yyyy-MMMM-dd HH:mm:ss");
        Date date = new Date();
        return dateFormat.format(date);
    }
    
   /**
   * generate key store file & cert file, then export them
   */
    public static void generateKeyStoreAndCertFile() throws Exception
    {
        //get keystore object and load it
        keyStore = KeyStore.getInstance("CaseExactJKS");
        keyStore.load(null, null);

        //generate a keypair
        CertAndKeyGen keypair = new CertAndKeyGen("RSA", "SHA256withRSA", null);
        keypair.generate(keysize);
            
        //get private key from the keypair
        privKey = keypair.getPrivateKey();

        X500Name x500Name = new X500Name(commonName, organizationalUnit, organization, city, state, country);
        X509Certificate[] chain = new X509Certificate[1];

        chain[0] = keypair.getSelfCertificate(x500Name, new Date(), (long) validity * 24 * 60 * 60);
                
        //set keystore entry and export it
        keyStore.setKeyEntry(alias, privKey, keyPass, chain);
        keyStore.store(new FileOutputStream(".keystore"), keyPass);
            
        //get X509certificate from keystore by using string alias
        cert = (X509Certificate) keyStore.getCertificate(alias);
               
        //write the encoded cert file in PEM format and export
        FileWriter fw = new FileWriter(certFilePath);
        fw.write(certToString(cert));
        fw.close();
    }
    
   /**
   * load key store file & get private key from it
   */
    public static void loadKeyStoreAndGetPrivKey() throws Exception
    {
        //get keystore object 
        keyStore = KeyStore.getInstance("CaseExactJKS");
            
        //read keystore file path
        FileInputStream readStream = new FileInputStream(keystoreFilePath);
            
        //load keystore with file path and password
        keyStore.load(readStream, keyPass);
            
        //get X509certificate from keystore by using string alias
        cert = (X509Certificate) keyStore.getCertificate(alias);
            
        // get my private key
        ProtectionParameter keyPasswordParam = new PasswordProtection(keyPass);
        KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry(alias,keyPasswordParam);
        privKey = pkEntry.getPrivateKey();
            
        //close readStream
        readStream.close();
    }
    
   /**
   * hash string and return hashed string in hex format
   */
    public static String hashStringWithSHA(String json) throws Exception{
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(json.getBytes("UTF-8"));

        byte byteData[] = md.digest();
        
        //convert the byte to hex format
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < byteData.length; i++) {
         sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
        }
        
        return sb.toString();
    }
    
   /**
   * convert bytes to hex
   */
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
    
   /**
   * split a string into 3 parts 
   */
    public static String[] splitEqually(String src, int len) {
        String[] result = new String[(int)Math.ceil((double)src.length()/(double)len)];
        for (int i=0; i<result.length; i++)
            result[i] = src.substring(i*len, Math.min(src.length(), (i+1)*len));
        return result;
    }
    
   /**
   * decide the splitting length
   */
    public static int whereToSplit(int hashLength) {
        //if length number is even number then split equal, else add one more char for first value
        if(hashLength%3==0){
          return hashLength/3;
        }else{
          while(hashLength%3!=0){
              hashLength = hashLength+1;
          }
          return hashLength/3;
        }
    }
}
