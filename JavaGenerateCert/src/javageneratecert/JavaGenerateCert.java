/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package javageneratecert;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
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
import java.security.cert.CertificateEncodingException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.json.simple.JSONObject;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

/**
 *
 * @author CheahHong
 */
public class JavaGenerateCert {
    
    private static final int keysize = 1024;
    private static final String commonName = "www.test.de";
    private static final String organizationalUnit = "IT";
    private static final String organization = "test";
    private static final String city = "test";
    private static final String state = "test";
    private static final String country = "DE";
    private static final long validity = 1096; // 3 years
    private static final String alias = "tomcat";
    private static final char[] keyPass = "changeit".toCharArray();
    
    private static final String keystoreFilePath = "C:\\Users\\CheahHong\\Desktop\\Java-Server-Side-Encryption\\JavaGenerateCert\\.keystore";
    private static final String certFilePath = "C:\\Users\\CheahHong\\Desktop\\Java-Server-Side-Encryption\\JavaGenerateCert\\cacert.pem";
    private static final String locationFilePath = "C:\\Users\\CheahHong\\Desktop\\test.txt";
    
    private static PrivateKey privKey;
    private static KeyStore keyStore;
    private static X509Certificate cert;
    
   /**
    * @param args the command line arguments
    */
    @SuppressWarnings("restriction")
    public static void main(String[] args) throws Exception{
        
        if(areKeyStorePresent()) { 
            System.out.println("Keystore file & Certificate exist\n");
            loadKeyStoreAndGetPrivKey();
        }else{
            System.out.println("Created Keystore file & Certificate PEM file\n");
            generateKeyStoreAndCertFile();
        }
        
        System.out.println("Private Key: "+privKey);
        System.out.println("KeyStore: "+keyStore+"\n");
        
        //open a server socket to listen requests
        ServerSocket server = new ServerSocket(7080);
        int counter=0;
        System.out.println("Listening for connection on port 7080 ....\n");
        while (true) {
            try (Socket socket = server.accept()) {
                System.out.println("Server received request: "+counter);
                JSONObject jsonObjForData = new JSONObject();
                JSONObject jsonObjForKeyAndData = new JSONObject();
                counter++;
                
                //read location data from file
                String locationData = readFile(locationFilePath,StandardCharsets.UTF_8);
                
                //encrypted location data
                //byte[] encryptedLocation = encrypt(locationData,privKey);
                //System.out.println("Encrypted Location Data: "+encryptedLocation);
                //get base64 encoded version of the encrypted location data
                //String encodedData = Base64.getEncoder().encodeToString(encryptedLocation);
                //System.out.println("Encoded EncryptedData: "+encodedData);
                
                //generate a Symmetric Key
                Key secretKey = generateSymmetricKey();
                
                // get base64 encoded version of the key
                String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
                System.out.println("Original Secret Key: "+encodedKey);
                
                //encrypt the secretKey using private key
                byte[] encryptedKey = encrypt(encodedKey,privKey);
                
                //get base64 encoded version of the encrypted key
                String encodedEncryptedKey = Base64.getEncoder().encodeToString(encryptedKey);
                System.out.println("Encoded Encrypted Key: "+encodedEncryptedKey);
                
                //decrypt key using Public Key (testing)
                PublicKey pubKey = cert.getPublicKey();
                String decryptedKey = decrypt(encryptedKey,pubKey);
                System.out.println("Decrypted Key: "+decryptedKey );
                
                //put the location data, random and currenDateTime in json object
                jsonObjForData.put("location", new String(locationData));
                jsonObjForData.put("randomNumber",getRandNumber());
                jsonObjForData.put("currentDateTime",new String(getCurrentDateTime()));
                System.out.println("Original Json Data: "+jsonObjForData.toString());
                
                //encrypt the json string using Symmetric Key
                byte[] encryptedJson = encrypt(jsonObjForData.toString(),secretKey);
                
                //get base64 encoded version of the encrypted json data
                String encodedEncryptedData = Base64.getEncoder().encodeToString(encryptedJson);
                System.out.println("Encoded Encrypted Json Data: "+encodedEncryptedData);
                
                //decrypt json using Symmetric Key (testing)
                String decryptedJsonData = decrypt(encryptedJson,secretKey);
                System.out.println("Decrypted Json Data: "+decryptedJsonData +"\n");
                
                //put encoded versions of the encrypted json data and encrypted symmetric key in json Obj
                jsonObjForKeyAndData.put("encodedEncryptedJson",encodedEncryptedData);
                jsonObjForKeyAndData.put("encodedEncryptedKey",encodedEncryptedKey);
                
                //Output the response string
                String httpResponse = "HTTP/1.1 200 OK\r\n\r\n" + jsonObjForKeyAndData.toString();
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
   * Encrypt the plain text using symmetric key OR
   * Encrypt symmetric key using private key
   * 
   * @param text
   *          : original plain text
   * @param key
   *          :Secret Key/The private key
   * @return Encrypted text
   * @throws java.lang.Exception
   */
    public static byte[] encrypt(String text, Key key) {
      byte[] cipherText = null;
      try {
        // get an RSA cipher object and print the provider
        final Cipher cipher = Cipher.getInstance(key.getAlgorithm());
        
        // encrypt the plain text using the private key
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipherText = cipher.doFinal(text.getBytes());
      } catch (Exception e) {
        e.printStackTrace();
      }
      return cipherText;
   }
   
   /**
   * Decrypt text using public key OR
   * Decrypt Symmetric Key using public key
   * 
   * @param text
   *          :encrypted text
   * @param key
   *          :Secret Key/The public key
   * @return plain text
   * @throws java.lang.Exception
   */
    public static String decrypt(byte[] text, Key key) {
      byte[] decryptedText = null;
      try {
        // get an RSA cipher object and print the provider
        final Cipher cipher = Cipher.getInstance(key.getAlgorithm());

        // decrypt the text using the public key
        cipher.init(Cipher.DECRYPT_MODE, key);
        decryptedText = cipher.doFinal(text);

      } catch (Exception ex) {
        ex.printStackTrace();
      }

      return new String(decryptedText);
    }
    
   /**
   * Read all text from file
   * 
   * @param path
   *          :path to the text file
   * @param encoding 
   *          :The type of CharSet
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
        DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
        Date date = new Date();
        return dateFormat.format(date);
    }
    
   /**
   * Get a random number range from 1 to 100,000
   */
    public static int getRandNumber()
    {
        Random rand = new Random(); 
        int value = rand.nextInt((9999999 - 1) + 1) + 1;
        return value;
    }
    
   /**
   * generate key store file & cert file, then export them
   */
    public static void generateKeyStoreAndCertFile() throws Exception
    {
        //get keystore object and load it
        keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);

        //generate a keypair
        CertAndKeyGen keypair = new CertAndKeyGen("RSA", "SHA1WithRSA", null);
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
        keyStore = KeyStore.getInstance("JKS");
            
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
   * generate and return a symmetric key
   */
    public static Key generateSymmetricKey() throws Exception {
	KeyGenerator generator = KeyGenerator.getInstance( "AES" );
	SecretKey key = generator.generateKey();
	return key;
    }
}
