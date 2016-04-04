/*
 * Copyright 2014 Aymen.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package me.aymen.util;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
//import 

/**
 * Utility to generate several Key Store associated objects
 *
 * @author Aymen Alquaiti
 * @Date 13/09/2014
 */
public class KeyStoreUtil
{
    // Public Final Fields used for Key Pair generation

    /**
     * Default Algorithm used for Key Pair generation, which is RSA
     */
    public static final String DEFAULT_KEY_ALGORITHM = "RSA";

    /**
     * Default key size used for key pair generation, which equals to 1024 Bit
     */
    public static final int DEFAULT_KEY_SIZE = 1024;

    // Public Final Fields used for X509Certificate v3 generation
    /**
     * Default Issuer destination name which is set as follows:<br/>
     * CN=localhost, OU=UNKNOWN, O=UNKNOWN, L=UNKNOWN, C=UNKNOWN
     */
    public static final X509Principal DEFAULT_ISSUER_DN = new X509Principal("CN=localhost, OU=UNKNOWN, O=UNKNOWN, L=UNKNOWN, C=UNKNOWN");
    /**
     * Default Subject destination name which is set as follows:<br/>
     * CN=localhost, OU=UNKNOWN, O=UNKNOWN, L=UNKNOWN, C=UNKNOWN
     */

    public static final X509Principal DEFAULT_SUBJECT_DN = DEFAULT_ISSUER_DN;
    /**
     * Default Not Before date used for X509Certificate v3 generation, which is
     * equal to System's current date minus one month in the pas
     */

    public static final Date DEFAULT_NOTBEFORE_DATE = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30);
    /**
     * Default Not After date used for X509Certificate v3 generation, which is
     * equal to System's current date plus 10 years to the future
     */

    public static final Date DEFAULT_NOTAFTER_DATE = new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365 * 10));
    /**
     * Default algorithm used for signing X509Certificate v3, which is equal to
     * "MD5WithRSAEncryption"
     */
    public static final String DEFAULT_SIGN_ALGORITHM = "MD5WithRSAEncryption";

    // Public Final Fields used for Key Store generation
    /**
     * Default alias name for private key, which is equal to "CERTALIAS"
     */
    public static final String DEFAULT_ALIAS = "CERTALIAS";

    /**
     * Default key store type, which is equal to "JKS"
     */
    public static final String DEFAULT_KEYSTORE_TYPE = "JKS";
    
    /**
     * Default Key Store and key password
     */
    public static final String DEFAULT_PASS = "changeit";

    /**
     * Generate Key Pair using RSA Algorithm with 1024 Bit key size.
     *
     * @return KeyPair object
     * @throws NoSuchAlgorithmException if RSA Algorithm is not supported, which
     * should never happen.
     */
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException
    {
        return generateKeyPair(DEFAULT_KEY_ALGORITHM, DEFAULT_KEY_SIZE);
    }

    /**
     * Generate Key Pair using specified Algorithm and key size.
     *
     * @param algorithm Key Pair algorithm used to generate keys
     * @param keySize Key Size. The larger the key the more secure the
     * encryption but the slowest the processing time to decrypt/encrypt. Don't
     * use a key size less 1024
     * @return KeyPair object
     * @throws NoSuchAlgorithmException if algorithm is not supported
     */
    public static KeyPair generateKeyPair(String algorithm, int keySize) throws NoSuchAlgorithmException
    {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        return keyPair;
    }

    /**
     * Generate X509 Certificate version 3 with default settings
     *
     * @return X509Certificate of version 3
     * @throws SecurityException
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     */
    public static X509Certificate generateCertificate() throws SecurityException, SignatureException, InvalidKeyException, NoSuchAlgorithmException
    {
        return generateCertificate(generateKeyPair());
    }

    /**
     * Generate X509 Certificate version 3. Key Pair is generated automatically
     * with all default settings used.
     *
     * @param domain Domain Name for Issuer and Subject Destination name
     * @return X509Certificate of version 3
     * @throws SecurityException
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     */
    public static X509Certificate generateCertificate(String domain) throws SecurityException, SignatureException, InvalidKeyException, NoSuchAlgorithmException
    {
        return generateCertificate(domain, generateKeyPair());
    }

    /**
     * Generate X509 Certificate version 3 using default settings
     *
     * @param keyPair Key Pair used to generate certificate
     * @return X509Certificate of version 3
     * @throws SecurityException
     * @throws SignatureException
     * @throws InvalidKeyException
     */
    public static X509Certificate generateCertificate(KeyPair keyPair) throws SecurityException, SignatureException, InvalidKeyException
    {
        return generateCertificate("localhost", keyPair);
    }

    /**
     * Generate X509 Certificate version 3. Serial number is generated
     * automatically. Not before date, not after date and signing algorithm are
     * set to default. See {@link KeyStoreUtil#DEFAULT_NOTBEFORE_DATE},
     *
     * @param domain Domain Name for Issuer and Subject Destination name
     * @param keyPair Key Pair used to generate certificate
     * @return X509Certificate of version 3
     * @throws SecurityException
     * @throws SignatureException
     * @throws InvalidKeyException
     */
    public static X509Certificate generateCertificate(String domain, KeyPair keyPair) throws SecurityException, SignatureException, InvalidKeyException
    {
        String dn = "CN=" + domain + ", OU=UNKNOWN, O=UNKNOWN, L=UNKNOWN, C=UNKNOWN";
        return generateCertificate(new X509Principal(dn), new X509Principal(dn), keyPair);
    }

    /**
     * Generate X509 Certificate version 3. Serial number is generated
     * automatically. Not before date, not after date and signing algorithm are
     * set to default. See {@link KeyStoreUtil#DEFAULT_NOTBEFORE_DATE},
     * {@link KeyStoreUtil#DEFAULT_NOTAFTER_DATE} and
     * {@link KeyStoreUtil#DEFAULT_SIGN_ALGORITHM} respectively.
     *
     * @param issuer to set issuer destination name
     * @param subject to set subject destination name
     * @param keyPair Key Pair used to generate certificate
     * @return X509Certificate of version 3
     * @throws SecurityException
     * @throws SignatureException
     * @throws InvalidKeyException
     */
    public static X509Certificate generateCertificate(X509Principal issuer, X509Principal subject, KeyPair keyPair) throws
            SecurityException, SignatureException, InvalidKeyException
    {
        return generateCertificate(issuer, subject, keyPair, DEFAULT_NOTBEFORE_DATE, DEFAULT_NOTAFTER_DATE);
    }

    /**
     * Generate X509 Certificate version 3. Serial number is generated
     * automatically, and signing algorithm is set to default. See
     * {@link KeyStoreUtil#DEFAULT_SIGN_ALGORITHM}.
     *
     * @param issuer to set issuer destination name
     * @param subject to set subject destination name
     * @param keyPair Key Pair used to generate certificate
     * @param notBefore Beginning date/time of the certificate
     * @param notAfter Ending date/time of the certificate
     * @return X509Certificate of version 3
     * @throws SecurityException
     * @throws SignatureException
     * @throws InvalidKeyException
     */
    public static X509Certificate generateCertificate(X509Principal issuer, X509Principal subject, KeyPair keyPair,
            Date notBefore, Date notAfter) throws SecurityException, SignatureException, InvalidKeyException
    {
        int serial = new SecureRandom().nextInt();

        if (serial < 0)
        {
            serial = serial * -1;
        }

        return generateCertificate(issuer, subject, keyPair, notBefore, notAfter,
                BigInteger.valueOf(serial), DEFAULT_SIGN_ALGORITHM);
    }

    /**
     * Generate X509 Certificate version 3
     *
     * @param issuer to set issuer destination name
     * @param subject to set subject destination name
     * @param keyPair Key Pair used to generate certificate
     * @param notBefore Beginning date/time of the certificate
     * @param notAfter Ending date/time of the certificate
     * @param serial Certificate serial number
     * @param signAlgorithm Algorithm to use for signing the certificate
     * @return X509Certificate of version 3
     * @throws SecurityException
     * @throws SignatureException
     * @throws InvalidKeyException
     */
    public static X509Certificate generateCertificate(X509Principal issuer, X509Principal subject,
            KeyPair keyPair, Date notBefore, Date notAfter, BigInteger serial, String signAlgorithm) throws
            SecurityException, SignatureException, InvalidKeyException
    {
        Security.addProvider(new BouncyCastleProvider());
        X509V3CertificateGenerator certificateGen = new X509V3CertificateGenerator();
        certificateGen.setIssuerDN(issuer);
        certificateGen.setSubjectDN(subject);
        certificateGen.setSerialNumber(serial);

        certificateGen.setNotBefore(notBefore);
        certificateGen.setNotAfter(notAfter);
        certificateGen.setPublicKey(keyPair.getPublic());
        certificateGen.setSignatureAlgorithm(signAlgorithm);

        X509Certificate certificate = certificateGen.generateX509Certificate(keyPair.getPrivate());

        return certificate;
    }

    /**
     * Generate Key Store that holds Private/Public Key with X509 Certification.
     * Key Store password and Key password are given the value of {@link KeyStoreUtil#DEFAULT_PASS}
     *
     * @return Key Store initialized in memory
     * @throws KeyStoreException
     * @throws java.security.SignatureException
     * @throws IOException
     * @throws java.security.InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     */
    public static KeyStore generateKeyStore() throws SecurityException, SignatureException,
            InvalidKeyException, NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException
    {
        return generateKeyStore(generateKeyPair());
    }

    /**
     * Generate Key Store that holds Private/Public Key with X509 Certification
     *
     * @param storePass Key Store password
     * @param keyPass Key password
     * @return Key Store initialized in memory
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws java.security.SignatureException
     * @throws java.security.InvalidKeyException
     */
    public static KeyStore generateKeyStore(String storePass, String keyPass) throws KeyStoreException,
            IOException, NoSuchAlgorithmException, CertificateException, SecurityException,
            SignatureException, InvalidKeyException
    {
        return generateKeyStore(generateKeyPair(), storePass, keyPass);
    }

    /**
     * Generate Key Store that holds Private/Public Key with X509 Certification.
     * Password 
     *
     * @param keyPair Key Pair that holds public and private key
     * @return Key Store initialized in memory
     * @throws KeyStoreException
     * @throws java.security.SignatureException
     * @throws IOException
     * @throws java.security.InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     */
    public static KeyStore generateKeyStore(KeyPair keyPair) throws SecurityException, SignatureException,
            InvalidKeyException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException
    {
        X509Certificate certificate = generateCertificate(keyPair);

        return generateKeyStore(keyPair, certificate);
    }

    /**
     * Generate Key Store that holds Private/Public Key with X509 Certification
     * Key Store password and Key password are given the value of {@link KeyStoreUtil#DEFAULT_PASS}
     * @param keyPair Key Pair that holds public and private key
     * @param storePass Key Store password
     * @param keyPass Key password
     * @return Key Store initialized in memory
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws java.security.SignatureException
     * @throws java.security.InvalidKeyException
     */
    public static KeyStore generateKeyStore(KeyPair keyPair, String storePass, String keyPass)
            throws KeyStoreException, IOException, NoSuchAlgorithmException,
            CertificateException, SecurityException, SignatureException, InvalidKeyException
    {
        X509Certificate certificate = generateCertificate(keyPair);

        return generateKeyStore(keyPair, certificate, storePass, keyPass);
    }

    /**
     * Generate Key Store that holds Private/Public Key with X509 Certification.
     * Key Store password and Key password are given the value of {@link KeyStoreUtil#DEFAULT_PASS}
     *
     * @param keyPair Key Pair that holds public and private key
     * @param certificate X509 certification
     * @return Key Store initialized in memory
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     */
    public static KeyStore generateKeyStore(KeyPair keyPair, X509Certificate certificate) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException
    {
        String storePass = DEFAULT_PASS;
        String keyPass = DEFAULT_PASS;

        return generateKeyStore(generateKeyPair(), certificate, storePass, keyPass);
    }

    /**
     * Generate Key Store that holds Private/Public Key with X509 Certification
     *
     * @param keyPair Key Pair that holds public and private key
     * @param certificate X509 certification
     * @param storePass Key Store password
     * @param keyPass Key password
     * @return Key Store initialized in memory
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     */
    public static KeyStore generateKeyStore(KeyPair keyPair, X509Certificate certificate, String storePass, String keyPass)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException
    {
        return generateKeyStore(keyPair, certificate, DEFAULT_KEYSTORE_TYPE, DEFAULT_ALIAS, storePass, keyPass);
    }

    /**
     * Generate Key Store that holds Private/Public Key with X509 Certification
     *
     * @param keyPair Key Pair that holds public and private key
     * @param certificate X509 certification
     * @param type Key Store type
     * @param alias Key alias name
     * @param storePass Key Store password
     * @param keyPass Key password
     * @return Key Store initialized in memory
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     */
    public static KeyStore generateKeyStore(KeyPair keyPair, X509Certificate certificate,
            String type, String alias, String storePass, String keyPass)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException
    {
        KeyStore keyStore = KeyStore.getInstance(type);
        keyStore.load(null, storePass.toCharArray());
        keyStore.setKeyEntry(alias, keyPair.getPrivate(), keyPass.toCharArray(), new java.security.cert.Certificate[]
        {
            certificate
        });

        return keyStore;
    }

    /**
     * Saves X509 Certificate to File
     *
     * @param certificate X509 Certificate to save
     * @param name File path including name and extension
     * @throws FileNotFoundException
     * @throws IOException
     * @throws CertificateEncodingException
     */
    public static void saveToFile(X509Certificate certificate, String name)
            throws FileNotFoundException, IOException, CertificateEncodingException
    {
        try (FileOutputStream fos = new FileOutputStream(name))
        {
            fos.write(certificate.getEncoded());
        }
    }

    /**
     * Save Key Store to File
     *
     * @param keyStore KeyStore to save
     * @param storePass store password
     * @param name File path including name and extension
     * @throws FileNotFoundException
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     */
    public static void saveToFile(KeyStore keyStore, String storePass, String name)
            throws FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException
    {
        FileOutputStream fOut = new FileOutputStream(name);
        keyStore.store(fOut, storePass.toCharArray());
    }

    /**
     * Retrieve X509 Certificate from a site. This method avoid checking if host's
     * certificate is trusted
     * @param host site name
     * @param port secured port
     * @return Array of found X509 certificates
     * @throws NoSuchAlgorithmException
     * @throws KeyManagementException
     * @throws IOException 
     */
    public static X509Certificate[] retrieveTLS(String host, int port) 
                                        throws NoSuchAlgorithmException, KeyManagementException, IOException
    {
        TrustManager trm = new X509TrustManager()
        {
            @Override
            public X509Certificate[] getAcceptedIssuers()
            {
                return null;
            }

            @Override
            public void checkClientTrusted(X509Certificate[] certs, String authType)
            {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] certs, String authType)
            {
            }
        };

        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, new TrustManager[]
        {
            trm
        }, null);
        SSLSocketFactory factory = sc.getSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
        socket.startHandshake();
        SSLSession session = socket.getSession();
        return (X509Certificate[]) session.getPeerCertificates();
    }
}
