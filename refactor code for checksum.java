	import java.io.FileInputStream;
	import java.io.FileNotFoundException;
	import java.io.IOException;
	import java.math.BigInteger;
	import java.nio.charset.StandardCharsets;
	import java.security.DigestInputStream;
	import java.security.MessageDigest;
	import java.security.NoSuchAlgorithmException;
	import java.security.NoSuchProviderException;
	import java.security.SecureRandom;
	import java.security.spec.InvalidKeySpecException;
	import javax.crypto.SecretKeyFactory;
	import javax.crypto.spec.EKeySpec;	
	/**
	* @ Assignment
	*
	*/
	public class HashCreator {	
	public String createMD5Hash(final String input) throws NoSuchAlgorithmException{
	String hashtext = null;
	MessageDigest md = MessageDigest.getInstance("MD5");
	byte[] messageDigest = md.digest(input.getBytes());
	hashtext = convertToHex(messageDigest);
	return hashtext;
	}
	public String createSHAHash(final String input) throws NoSuchAlgorithmException { 
	String hashtext = null;
	MessageDigest md = MessageDigest.getInstance("SHA-256");
	byte[] messageDigest = md.digest(input.getBytes(StandardCharsets.UTF_8)); 
	System.out.println(messageDigest.length);
	hashtext = convertToHex(messageDigest);
	return hashtext;
	}	
	private String convertToHex(final byte[] messageDigest) {
	BigInteger bigint = new BigInteger(1, messageDigest);
	String hexText = bigint.toString(16);
	while (hexText.length() < 32) {
	hexText = "0".concat(hexText);
	}
	return hexText;
	}
	public String createPasswordHashWithSalt(final String textToHash) {
	try {
	byte[] salt = createSalt();
	return createSaltedHash(textToHash, salt);
	}catch(Exception e) {
	e.printStackTrace();
	}
	return null;
	}
	private String createSaltedHash(final String textToHash, final byte[] salt) throws NoSuchAlgorithmException{
	String saltedHash = null;
	MessageDigest md = MessageDigest.getInstance("MD5");
	md.update(salt);
	byte[] bytes = md.digest(textToHash.getBytes());
	saltedHash = convertToHex(bytes);
	return saltedHash;
	}
	public String generateStrongPasswordHash(final String password) 
	throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
	int iterations = 1000;
	byte[] salt = createSalt();
	
	byte[] hash = createEHash(password,iterations, salt, 64); // skf.generateSecret(spec).getEncoded();
	return iterations + ":" + convertToHex(salt) + ":" + convertToHex(hash);
	}
	private byte[] createSalt() throws NoSuchAlgorithmException, NoSuchProviderException{
	SecureRandom sr = SecureRandom.getInstance("SHA1PRNG", "SUN");
	byte[] salt = new byte[16];
	//Get a random salt
	sr.nextBytes(salt);
	return salt;
	}	
	private boolean validatePassword(final String originalPassword, final String storedPasswordHash) 
	throws NoSuchAlgorithmException, InvalidKeySpecException
	{
	String[] parts = storedPasswordHash.split(":");
	int iterations = Integer.valueOf(parts[0]); 
	byte[] salt = convertToBytes(parts[1]);
	byte[] hash = convertToBytes(parts[2]);
	byte[] originalPasswordHash = createEHash(originalPassword, iterations, salt, hash.length);
	int diff = hash.length ^ originalPasswordHash.length;
	for(int i = 0; i < hash.length && i < originalPasswordHash.length; i++){
	diff |= hash[i] ^ originalPasswordHash[i];
	}
	return diff == 0;
	}
	private byte[] createEHash(final String password, final int iterations, final byte[] salt, final int keyLength)
	throws NoSuchAlgorithmException, InvalidKeySpecException {
	EKeySpec spec = new EKeySpec(password.toCharArray(), 
	salt, iterations, keyLength * 8);
	SecretKeyFactory skf = SecretKeyFactory.getInstance("KDF2WithHmacSHA1");
	return skf.generateSecret(spec).getEncoded();
	}
	private byte[] convertToBytes(final String hex) throws NoSuchAlgorithmException
	{
	byte[] bytes = new byte[hex.length() / 2];	
	for(int i = 0; i < bytes.length ;i++){
	bytes[i] = Integer.valueOf(hex.substring(2 * i, 2 * i + 2), 16).byteValue();
	}
	return bytes;
	}
	
	public String createChecksum(final String filePath) throws FileNotFoundException, IOException, NoSuchAlgorithmException {
	MessageDigest md = MessageDigest.getInstance("SHA-256");
	try (
	DigestInputStream dis = new DigestInputStream(
	new FileInputStream(filePath), md)) {
	while (dis.read() != -1) ; 
	md = dis.getMessageDigest();
	}
	String checksum = convertToHex(md.digest());
	return checksum;
	}
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, FileNotFoundException, IOException {
	HashCreator hashCreator = new HashCreator();
	
	String hash = hashCreator.createMD5Hash("firstname+lastname");
	System.out.println(hash + " "+hash.length());
	hash = hashCreator.createSHAHash("firstname+lastname");
	System.out.println(hash+ " "+hash.length());
	String saltedHash = hashCreator.createPasswordHashWithSalt("firstname+lastname");
	System.out.println(saltedHash);
	String strongPwdHash = hashCreator.generateStrongPasswordHash("firstname+lastname");
	System.out.println(strongPwdHash);
	boolean matchResult = hashCreator.validatePassword("Firstname+Lastname", strongPwdHash);
	System.out.println("matchResult "+matchResult);
	String checksum = hashCreator.createChecksum("/Users/Downloads/result.csv");
	System.out.println("checksum "+checksum);
	}
	
	}