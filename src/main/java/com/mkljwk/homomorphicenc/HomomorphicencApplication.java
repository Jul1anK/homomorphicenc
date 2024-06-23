package com.mkljwk.homomorphicenc;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.Statement;
import java.util.HashMap;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.n1analytics.paillier.EncryptedNumber;
import com.n1analytics.paillier.PaillierContext;
import com.n1analytics.paillier.PaillierPrivateKey;
import com.n1analytics.paillier.PaillierPublicKey;


@SpringBootApplication
public class HomomorphicencApplication implements CommandLineRunner{

	
	public static PaillierPrivateKey ok(
			BigInteger p,
			BigInteger q
			) throws NoSuchMethodException, SecurityException, InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {

	    BigInteger modulus;
	  
	    modulus = p.multiply(q);
	    
	    final PaillierPublicKey publicKey = new PaillierPublicKey(modulus);
	    
	    Constructor<PaillierPrivateKey> c = PaillierPrivateKey.class.getDeclaredConstructor(PaillierPublicKey.class, BigInteger.class, BigInteger.class);
	    
	    c.setAccessible(true);
	    PaillierPrivateKey result = c.newInstance(publicKey, p, q);
	    c.setAccessible(false);
	    
	    return result;//new PaillierPrivateKey(publicKey, p, q);
		
	}
	
	public void sumArray() {
		
	}
	
	public static BigInteger toBigInteger(String foo)
	{
	    return new BigInteger(foo.getBytes());
	}

	public static String fromBigInteger(BigInteger bar)
	{
	    return new String(bar.toByteArray());
	}
	
	
	public static EncryptedNumber encryptString(PaillierContext context, String str) {
		
		BigInteger data = toBigInteger(str);
		
		return context.encrypt(data);
		
	}
	
	public static String decrypt(PaillierPrivateKey context, EncryptedNumber data) {
		
		return fromBigInteger(context.decrypt(data).decodeBigInteger());
		
	}
	
	public static void main(String[] args) {
		SpringApplication.run(HomomorphicencApplication.class, args);
	}

	@Autowired
	DataSource ds;
	
	@Override
	public void run(String... args) throws Exception {
		
		//PrintStream fileStream = new PrintStream(new File("out_log.txt"));
		
        // Redirect the error stream to the file
       // System.setOut(fileStream);
		
		BigInteger q = new BigInteger("9416603184959278740617919082252225879900914123492195044368348465249494941968791109171998436027710997693628088344819345345734187178145024665672700667475421");
		BigInteger p = new BigInteger("12483493444046649060699286161536906873404627907731339579734908469731632322085430151661084130379517720082040601403505235617053243444499170494494937539494213");
	
		
		
        PaillierPrivateKey privateKey = ok(p,q); 
        
        PaillierPublicKey publicKey = privateKey.getPublicKey();

        publicKey.getModulus();
        
        
        
        // Initialize the context
        PaillierContext context = publicKey.createSignedContext();

		
		 Connection connection = ds.getConnection();
		
		  Statement statement = connection.createStatement();
	        String sql = "SELECT * FROM DATA";

	        // Executing the query
	        ResultSet resultSet = statement.executeQuery(sql);

	        ResultSetMetaData rsmd = resultSet.getMetaData();
	        
	        for(int i = 1; i <= rsmd.getColumnCount(); i++) {
	        	System.out.println("\t"+rsmd.getColumnLabel(i) + " " + rsmd.getColumnClassName(i) + " " + rsmd.getColumnType(i) + " " + rsmd.getColumnTypeName(i));
	        	
	        }
	        
	        // grupa - sum(zarobki)
	        HashMap<EncryptedNumber, EncryptedNumber> data = new HashMap<>();
	        
	        
	        
	        
	        // Processing the result set
	        while (resultSet.next()) {
	        
	        	EncryptedNumber name = encryptString(context, resultSet.getString("name").stripTrailing());
	        	EncryptedNumber group = encryptString(context, resultSet.getString("grupa").stripTrailing());
	            EncryptedNumber zarobki = context.encrypt(resultSet.getDouble("zarobki"));
	        	
	        	
	        	if(data.containsKey(group)) {
	        		
	        		data.put(group, data.get(group).add(zarobki));
	        		
	        	} else {
	        		
	        		data.put(group, zarobki);
	        	}
	        	
	        	
	            
	            System.out.println("Name: " + name.calculateCiphertext().toString().substring(0, 10) + "...");
	            System.out.println("Grupa: " + group.calculateCiphertext().toString().substring(0, 10) + "...");
	            System.out.println(" Zarobki: " + zarobki.calculateCiphertext().toString().substring(0, 10) + "...");
	           
	        }
	        
	        System.out.println("grupa\t\t\tgrupa dec\t\tenczarobki\t\tzarobki dec");
	        for(EncryptedNumber groupName : data.keySet()) {
	        
	        	
	        	
	        	System.out.print("" + groupName.calculateCiphertext().toString().substring(0, 10) + "...");
	        	System.out.print("\t\t" + decrypt(privateKey, groupName).stripTrailing());
	        	System.out.print("\t\t\t" + data.get(groupName).calculateCiphertext().toString().substring(0, 10) + "...");
	        	System.out.println("\t\t" + data.get(groupName).decrypt(privateKey).decodeDouble());
	        	
	        }
	        
	        
	        

	        
	        // Closing the result set and statement
	        resultSet.close();
	        statement.close();
	        
	        
	        
	        Statement statement1 = connection.createStatement();
	        ResultSet resultSet1 = statement1.executeQuery("select GRUPA, SUM(ZAROBKI) FROM BITCH.DATA group by GRUPA");
	        
	        System.out.println("grupa\t\tzarobki");
	        while (resultSet1.next()) {
	        	System.out.println(resultSet1.getString(1).stripTrailing() + "\t\t" + resultSet1.getString(2));
	        	
	        }
	        
	        
	        
	        resultSet1.close();
	        statement1.close();
	        connection.close();
		
		
		
		
		
	}

}
