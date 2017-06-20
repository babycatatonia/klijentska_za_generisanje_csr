import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.util.ArrayList;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

public class GenerateCSR {


	public static void main(String a[]) throws Exception{
		Security.addProvider(new BouncyCastleProvider());
		ArrayList<String> args = new ArrayList<String>();
		for(String s: a){
			args.add(s);
		}
		
		String applicantInfo="C="+args.get(0)+", ";
		applicantInfo+="ST="+args.get(1)+", ";
		applicantInfo+="L="+args.get(2)+", ";
		applicantInfo+="O="+args.get(3)+", ";
		applicantInfo+="OU="+args.get(4)+", ";
		applicantInfo+="CN="+args.get(5)+", ";
		applicantInfo+="EMAILADDRESS="+args.get(6);
		
	
		
		//loading the BC provider and setting it as a default provider
		Provider bc = new BouncyCastleProvider();
		Security.insertProviderAt(bc, 1);
		
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048);
		KeyPair pair = gen.generateKeyPair();
		
		PrivateKey privateKey = pair.getPrivate();
		PublicKey publicKey = pair.getPublic();
		
		
		
		
		
		
		//http://www.bouncycastle.org/wiki/display/JA1/BC+Version+2+APIs
		ContentSigner signGen = new JcaContentSignerBuilder("SHA1withRSA").build(privateKey);
		
		X500Principal subject = new X500Principal(applicantInfo);
		PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);
		PKCS10CertificationRequest request = builder.build(signGen);
		
		OutputStream outputStream       = new FileOutputStream(System.getProperty("user.home") + "/Desktop/csr.txt");
		OutputStreamWriter output = new OutputStreamWriter(outputStream);
		
		
		PEMWriter pem = new PEMWriter(output);
		pem.writeObject(request);
		pem.close();
		
		KeyStoreReader ksr = new KeyStoreReader();
		
		java.security.cert.Certificate jcert = ksr.readCertificate("C:\\Users\\me\\Desktop\\temp.jks",
				"temp","temp");
		
		
		
		
		KeyStoreWriter ksw = new KeyStoreWriter();
		ksw.loadKeyStore(null, "admin".toCharArray());
		ksw.write("certcsr", privateKey, "temp".toCharArray(), jcert);
		ksw.saveKeyStore("C:\\Users\\me\\Desktop\\temp1.jks","admin".toCharArray() );
	}
	

}