/*--------------------------------------------------------

1. Paul Ponda / Date: 03/03/2021

2. Java version used, if not the official version for the class:
both of:
openjdk 9
openjdk 11.0.9 2020-10-20 LTS



3. Precise command-line compilation examples / instructions:
javac -cp "./gson-2.8.2.jar" *.java

4. Precise examples / instructions to run this program:
Open three terminal windows an run one of these commands in each. Edit the classpath to what is appropriate:
java -cp './out/:./src/lib/gson-2.8.2.jar' Blockchain 0
java -cp './out/:./src/lib/gson-2.8.2.jar' Blockchain 1
java -cp './out/:./src/lib/gson-2.8.2.jar' Blockchain 2


5. List of files needed for running the program.

 a. Blockchain.java
 b. BlockInput0.txt
 c. BlockInput1.txt
 d. BlockInput2.txt

5. Notes:

e.g.:

----------------------------------------------------------*/

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.PriorityBlockingQueue;

//Blockhain class
public class Blockchain {
    public static void main(String args[]) throws IOException, IllegalArgumentException {
        int serverMode = 1; // 0 = timed init; 1 = PID 2 init.

        int q_len = 6;
        int basekeyport = 4710;
        int baseUBport = 4820;
        int baseBCport = 4930;

        int PID;

        // Read the PID of the system from the command line and parse it as an Int.
        if (args.length >= 1){
            for(int i = 0; i < args[0].length(); i++) {
                if(Character.digit(args[0].charAt(i), 10) >= 0){
                    continue;
                } else {
                    throw new IllegalArgumentException("Usage: PID \"" + args[0] + "\" is not an Int") ;
                }
            }

            try {
                PID = Integer.parseInt(args[0]);
                if (PID > 2) {
                    System.out.println("Not a valid PID, must be in range {0,1,2}");
                    System.exit(1);
                }
            } catch ( NumberFormatException e ){
                System.out.println("Error occurred reading PID");
                throw new NumberFormatException(e.getMessage());
            }

        } else {
            System.err.println("Usage: Specify PID number from {0,1,2}");
            System.exit(1);
            return;
        }


        System.out.println("Paul's Blockchain client v0.1a starting up");
        System.out.println("Starting as PID: " + PID + "\n\n");

        // Start the blockchain executor which will handle all the BlockChain coordination and the listeners.
        BCExecutor bce;
        try {
            bce = new BCExecutor(basekeyport, baseUBport, baseBCport, q_len, PID, serverMode);
        } catch (Exception e){
            System.out.println("ERROR: " + e.getMessage());
            return;
        }

        // Start up the Listeners before anything, using the executor.
        bce.startListeners();

        //Sleep for five seconds to wait for the other peers to start up.
        //todo: implement a node registration system for the peers. This is currently static.
        try{ Thread.sleep(5000);} catch(InterruptedException e)
        {
            System.out.println("Interrupted: " + e.getMessage());
            Thread.currentThread().interrupt();
        }

        if(serverMode == 0) {
            //First share public key with peers.
            //then begin processing my local database.
            bce.broadcastPublicKey();
            bce.startUVBProcessor();
            bce.processLocalPatientLedger();
        }

        // If using servermode 1, wait for PID 2 to start up.
        // only PID broadcasts it's public key to inform the other nodes
        // that it has started and class KeyWorker will initiate the other processes
        // once the public key is received.
        if(serverMode == 1 && PID == 2){
            bce.broadcastPublicKey();
        }

        /*
        // Print all of the providers supported on this system.
        for(int i = 0; i<Security.getProviders().length; i++) {
            System.out.println(Security.getProviders()[i].toString());
        }
        */

    }

}

// Contains a simple structure for the peer nodes.
// This is effectively hardcoded per the assignment instructions.
class BCPeer{
  int ID;
  PublicKey pubKey;
  int keyport;
  int UVBport;
  int BCport;
  String hostname;
}

// Container for the public key and sender PID
class EncodedPubKeyStruct {
    String encodedpubkey;
    String pid;

    EncodedPubKeyStruct(String key, int id){
        this.encodedpubkey = key;
        this.pid = Integer.toString(id);
    }
}

// Container for a signed Unverified Block.
class EncodedUVBStruct {
    String jsonUVB;
    String encodedSig;
    String pid;

    EncodedUVBStruct(String jsonUVB, String encodedSig, int id){
        this.jsonUVB = jsonUVB;
        this.pid = Integer.toString(id);
        this.encodedSig = encodedSig;
    }
}

// BCStruct - class for the blockchain object which is a collection of BlockRecords
class BCstruct {
    LinkedList<BlockRecord> recordList;

    // Initiate a new BlockChain
    BCstruct(int uid) {
        recordList = new LinkedList<BlockRecord>();

        try {
            recordList.add(new BlockRecord(uid));
        } catch (NoSuchAlgorithmException e) {
            System.out.println("ERROR: Could not initialize blockchain first record.");
        }
    }

    // simply get the First / Head of the queue.
    public BlockRecord getLastestBlock() {
        return recordList.getFirst();
    }

    // Add a record to the blockchain.
    // If the record fails to validate do not add and return false.
    public boolean addRecord(BlockRecord br, int pid) {

        // If this is the first block.
        if (this.recordList.size() == 0) {
            this.recordList.addFirst(br);
            return true;
        } else {
            // Check that prevHash matches
            if (br.previousHash.equals(this.getLastestBlock().createBlockRecordHash())) {
                //System.out.println("SUCCESS ADDING BLOCK");
                br.creditPID = Integer.toString(pid);
                this.recordList.addFirst(br);
                return true;
            } else {
                System.out.println("WILL NOT ADD BLOCK: previous has does not match");
                System.out.print(br.previousHash);
                System.out.print(" != ");
                System.out.print(this.getLastestBlock().createBlockRecordHash());
                System.out.print("\n");
                return false;
            }
        }
    }

    // The blockID is a unique in time identified for the transaction.
    // there can be many transactions in unverified space with the same
    // sequence number but all will have a unique ID.
    public boolean findBLockID(String uuidcheck) {
        for (int i = 0; i < this.recordList.size(); i++) {
            if (uuidcheck.equals(this.recordList.get(i).getBlockID())) {
                return true;
            }
        }
        return false;
    }

    //The sequence number. This is set by the owning PID process.
    // and corresponds to it's own transactions. Currently artificially
    // limited to 100 transactions.
    public boolean findBLockSeq(int seq) {
        for (int i = 0; i < this.recordList.size(); i++) {
            if (Integer.toString(seq).equals(this.recordList.get(i).seq)) {
                return true;
            }
        }
        return false;
    }

    // Compared the has of a provided block's previousBlock field with the
    // current top block and return true/false.
    public boolean checkPreviousHashMatch(BlockRecord br) {
        return br.previousHash.equals(this.getLastestBlock().createBlockRecordHash());
    }

    //pretty print the whole BlockChain to the console.
    public void printBC() {

        System.out.println("#### START PRINTING BlockChain ####");
        for (int i = 0; i < recordList.size(); i++) {
            System.out.println(" Record #: " + i);
            recordList.get(i).printBlockRecord();
            System.out.println("");
        }
        System.out.println("#### END PRINTING BlockChain ####\n");
    }

    //Get the length of the blockchain.
    public int getLength() {
        return recordList.size();
    }

    //Validate the entire blockchain.
    // this is done by checking the chain of previous hashes
    // and proof-of-work for each record.
    public boolean validateBC() {
        //We start at Block 1 (instead of 0) as we don't need to validate the dummy block.
        for (int i = 0; i < this.recordList.size() - 1; i++) {

            if (!this.recordList.get(i).previousHash.equals(this.recordList.get(i + 1).createBlockRecordHash())) {
                //System.out.println(this.recordList.get(i).previousHash);
                //System.out.println(this.recordList.get(i-1).createBlockRecordHash());
                return false;
            }
            if (!BCExecutor.verifyWork2(BCExecutor.difficulty, this.recordList.get(i))) {
                return false;
            }
        }
        return true;
    }

    //Validate the entire blockchain.
    // this is done by checking the chain of previous hashes
    // and proof-of-work for each record.
    public boolean validateVerboseBC() {
        //We start at Block 1 (instead of 0) as we don't need to validate the dummy block.
        System.out.println("Validating Blockchain:");
        for (int i = 0; i < this.recordList.size() - 1; i++) {

            int hashgood = 1;
            int workgood = 1;
            if (!this.recordList.get(i).previousHash.equals(this.recordList.get(i + 1).createBlockRecordHash())) {
                //System.out.println(this.recordList.get(i).previousHash);
                //System.out.println(this.recordList.get(i-1).createBlockRecordHash());
                hashgood = 0;
            }
            if (!BCExecutor.verifyWork2(BCExecutor.difficulty, this.recordList.get(i))) {
                workgood = 0;
            }

            int blocknum = this.recordList.size() - i;
            if(hashgood == 1 && workgood == 1){
                System.out.println("BLock " +  blocknum + ":  is valid");
            } else if(hashgood == 0 && workgood == 1){
                System.out.println("BLock " +  blocknum + ":  SHA-256 hash did not match previous block");
            } else if(hashgood == 1 && workgood == 0){
                System.out.println("BLock " +  blocknum + ":  Failed the proof-of-work");
            } else if(hashgood == 0 && workgood == 0){
                System.out.println("BLock " +  blocknum + ":  failed both SHA-256 and proof of work");
            }
        }
        return true;
    }
}

// BlockRecordComparator - provide a comparator for the Unverified Blocks priority queue.
// Uses the block timestamps as the sorting order with oldest processed first.
class BlockRecordComparator implements Comparator<BlockRecord>{
    @Override
    public int compare(BlockRecord a, BlockRecord b){
        DateFormat format;
        Date aa;
        Date bb;

        try {
            format = new SimpleDateFormat(a.DATEFORMAT, Locale.ENGLISH);
            aa = format.parse(a.timestamp);
            bb = format.parse(b.timestamp);
        } catch (IllegalArgumentException | ParseException e ){
            System.out.println("Comparator error - format given must be '" + a.DATEFORMAT + "'");
            throw new IllegalArgumentException(e.getMessage());
        }

        return aa.compareTo(bb);
    }
}

//Blockrecord class
class BlockRecord implements Serializable{
    final String DATEFORMAT = "yyyy-MM-dd.HH:mm:ss.S";
    private final int NONCE_LEN = 2; //in bytes
    private final String HASH_TYPE = "SHA-256";

    UUID BlockID;
    String Nonce;
    String previousHash;
    PatientRecord patientData;
    String timestamp;
    String userID;
    String seq;
    String datasig;
    String creditPID;

    BlockRecord(String patStr, String prevH, int uid){
        this(patStr, prevH, uid, UUID.randomUUID(),0);
    }

    BlockRecord(String patStr, String prevH, int uid, UUID uuid, int seq) {
        this.previousHash = prevH;
        this.BlockID = uuid;
        this.Nonce = "00000000";
        //new Random().nextBytes(this.Nonce);
        this.patientData = new PatientRecord(patStr);

        DateFormat df;
        Date currdate = new Date();
        try {
            df = new SimpleDateFormat(DATEFORMAT, Locale.ENGLISH);
            this.timestamp = df.format(currdate);
        } catch (IllegalArgumentException e){
            System.out.println("Error: Failed to properly initalize Block Record");
        }

        this.userID = "PID" + uid;
        this.seq = Integer.toString(seq);
    }


     //Initializes a null record (first record) as Jane Doe.
    BlockRecord(int uid) throws NoSuchAlgorithmException {
        this("Jane Doe 1900.01.01 000-00-0000 NA NA NA",
                "0000000000000000000000000000000000000000000000000000000000000000", uid);

        //this.previousHash = this.genBaseHash(algo);
    }

    // Print the currently reference block.
    public void printBlockRecord(){
        System.out.println(" *** Printing Block ***");
        System.out.println("BLOCK ID: " + this.BlockID.toString());
        System.out.println("Previous Hash: " + this.previousHash);
        System.out.println("Time Stamp: " + this.timestamp);
        System.out.println("Owner: " + this.userID);
        System.out.println("Sequence number: " + this.seq);
        System.out.println("Nonce: " + this.Nonce);
        System.out.println("DataSig: " + this.datasig);
        System.out.println("CreditPID: " + this.creditPID);
        System.out.println("Data: " + this.patientData.getPatientString());
        System.out.println(" *** End Block ***");
    }

    // Not used - could provide a more realistic base hash if neede.
    private static String genBaseHash(String algo) throws NoSuchAlgorithmException{
        MessageDigest md = MessageDigest.getInstance(algo);
        byte[] nullblock = new byte[256/8];
        for(int i = 0; i < nullblock.length; i++){
            nullblock[i] = 0x00;
        }

        nullblock = "hello, world!".getBytes();
        String H = byteToHexString(md.digest(nullblock));
        return H;
    }

    // byteToHexString - Helper function to convert any byte array to a hex string.
    public static String byteToHexString(byte[] mySHA) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < mySHA.length; i++) {
            //sb.append(Integer.toString((mySHA[i] & 0xff) + 0x100, 16).substring(1));
            String st =Integer.toHexString(mySHA[i] & 0xff);
            if (st.length() == 1) {
                sb.append('0' + st);
            } else{
                sb.append(st);
            }
        }
        return sb.toString();
    }

    // createBlockRecordHash - Fucntion that provides the SHA-256 hash value
    // of the object being referenced.
    public String createBlockRecordHash(){
        StringBuffer sb = new StringBuffer();
        byte[] blockdata;
        String myHash;

        /*
        Date currdate = new Date();
        try {
            df = new SimpleDateFormat(DATEFORMAT, Locale.ENGLISH);
            timestamp = df.format(currdate);
        } catch (IllegalArgumentException e){
            throw new IllegalArgumentException(e.getMessage());
        }
        */

        // order of data:
        // BlockID; PreviousHash; myProcessID (TBD); timestamp; nonce; data.
        sb.append(this.BlockID.toString());
        sb.append(this.previousHash);
        //sb.append(this.userID);
        //sb.append(this.timestamp);
        sb.append(this.Nonce);
        //sb.append(this.seq);

        byte[] sbbyte = sb.toString().getBytes(StandardCharsets.US_ASCII);
        byte[] databyte = patientData.getPatientString().getBytes(StandardCharsets.US_ASCII);

        /*

        blockdata = new byte[sbbyte.length + this.Nonce.length + databyte.length];

        int idx = 0;
        for(int i = 0; i < sbbyte.length; i++){
            blockdata[i + idx] = sbbyte[i];
        }

        idx = sbbyte.length;
        for(int i = 0; i < this.Nonce.length; i++){
            blockdata[i + idx] = this.Nonce[i];
        }

        idx = sbbyte.length + this.Nonce.length;
        for(int i = 0; i < databyte.length; i++){
            blockdata[i + idx] = databyte[i];
        }

         */

        blockdata = new byte[sbbyte.length + databyte.length];

        int idx = 0;
        for(int i = 0; i < sbbyte.length; i++){
            blockdata[i + idx] = sbbyte[i];
        }

        idx = sbbyte.length;
        for(int i = 0; i < databyte.length; i++){
            blockdata[i + idx] = databyte[i];
        }


        MessageDigest md;
        try {
         md = MessageDigest.getInstance(HASH_TYPE);
         myHash = byteToHexString(md.digest(blockdata));

        } catch (NoSuchAlgorithmException e){
            System.out.println("ERROR: Unknown algorithm in createBLockRecordHAsh");
            return "";
        }

        return myHash;
    }

    void signBlockData(PrivateKey privkey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        this.datasig = SecurityHelper.base64EncodeBytes(SecurityHelper.signData(this.patientData.getPatientString().getBytes(StandardCharsets.UTF_8), privkey));
    }

    public byte[] getDataSig(){
        return SecurityHelper.base64DecodeString(this.datasig);
    }

    public String getNonceToHexString(byte[] buff){
        return byteToHexString(buff);
    }

    public String getBlockID(){
        return BlockID.toString();
    }

    public UUID getBlockIDObj(){
        return this.BlockID;
    }

    public String getNonce() {
        return this.Nonce;
    }

    public void setNonce(String buff) {
        this.Nonce = buff;
    }

    public String getPreviousHash(){
        return this.previousHash;
    }

    public String getTimestamp() {
        return timestamp;
    }

    // Provide ability to reset the timestamp to the current time.
    // Helpful when a UVB has been rejected (other block won) and needs to be tried again.
    public void resetTimestamp() throws IllegalArgumentException{
        DateFormat df;
        Date currdate = new Date();
        df = new SimpleDateFormat(DATEFORMAT, Locale.ENGLISH);
        this.timestamp = df.format(currdate);
    }
}

//Collection of I/O type static functions for reading/writing files and JSON.
class IOHelper{
    // Reads the records file as a array of Strings for each line.
    public static String[] readRecordsFile(String filename) throws IOException{
        BufferedReader reader;
        ArrayList<String> tempStringList = new ArrayList<String>();
        String[] lines;


        try {
            reader = new BufferedReader(new FileReader(filename));
            String nextline = reader.readLine();
            while (nextline != null) {
                tempStringList.add(nextline);
                nextline = reader.readLine();
            }
            reader.close();
        } catch (FileNotFoundException e){
            throw new FileNotFoundException("Requested File " + filename + " not found");
        } catch (IOException e) {
            throw new IOException("Error reading file: " + filename);
        }

        lines = new String[tempStringList.size()];
        lines = tempStringList.toArray(lines);
        return lines;
    }

    // This function randomizes an array of any kind and
    // return that randomized array.
    // Java is pass by value. The original orderedArray is not modified.
    // Additional Comments: This function is relatively efficient as it swaps data in place in the array.
    //  assuming a each swap operation takes takes 3 memory operations (copy to temp, copy old, copy new) then
    //  the runtime should be 3 * n where n = array.length.
    static <T> T[] randomizer(T[] orderedArray){
        Random r = new Random();
        //T[] unorderedArray = new T[orderedArray.length];
        for (int i=0; i<orderedArray.length; i++){
            T tempval;
            int tempindex = r.nextInt(orderedArray.length);
            tempval = orderedArray[tempindex];
            orderedArray[tempindex] = orderedArray[i];
            orderedArray[i] = tempval;
        }
        return orderedArray;
    }

    //Gets JSON string from amd object.
    static <T> String getJSONFromObject(T objectforJSON){

        Gson gson = new GsonBuilder().setPrettyPrinting().create();

        // Convert the passed object to JSON
        String jstring = gson.toJson(objectforJSON);


        return jstring;
    }

    // Gets the object form a JSON string.
    static <T> T getObjectFromJSON(String jstr, Class<T> cls){

        Gson gson = new Gson();

        // Convert the passed string to object of given class.
        T jobj = gson.fromJson(jstr, cls);

        return jobj;
    }

    // unused - can read a JSON file that was written to disk and returns on object of the
    // referenced type.
    public static <T> T readJSONfile(String filename, Class<T> cls) throws IOException {
        BufferedReader bfr;
        Gson gson = new Gson();
        T jobj;

        try {
            bfr = new BufferedReader(new FileReader(filename));

            jobj = gson.fromJson(bfr, cls);

            bfr.close();
        } catch (FileNotFoundException e){
            throw new FileNotFoundException("Requested File " + filename + " not found");
            //return null;
        } catch (IOException e) {
            throw new IOException("Error reading file: " + filename);
            //return null;
        }

        return jobj;
    }

    // Writes a generic string to a file. JSON is a string so this function works for it.
    public static void writeStringToFile(String filename, String jstr) {
        // Write the JSON object to a file:
        try (FileWriter writer = new FileWriter(filename)) {
            writer.write(jstr);
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("Could not write string to " + filename);
        }
    }
}

// Data class for the supplied patient ledgers.
// This class is strict on the format of the input file and will fail if not exact, by design.
class PatientRecord{
    private final String DATEFORMAT = "yyyy.mm.dd";
    String firstName;
    String lastName;
    Date recordDate;
    String SSnum;
    String disease;
    String cure;
    String Rx;

    PatientRecord(String mypatientrecord) throws IllegalArgumentException{
        String[] recordparts = mypatientrecord.split("\\s+");

        //System.out.println(recordparts.length + recordparts[0]);
        if (recordparts.length != 7){
            throw new IllegalArgumentException("Record has missing or too much information");
        }
        this.firstName = recordparts[0];
        this.lastName = recordparts[1];
        parseRecordDate(recordparts[2]);
        this.SSnum = recordparts[3];
        this.disease = recordparts[4];
        this.cure = recordparts[5];
        this.Rx = recordparts[6];
    }

    private void parseRecordDate(String rdate) throws IllegalArgumentException{
        String[] datecomps = rdate.split("\\.");

        if (datecomps.length != 3){
            throw new IllegalArgumentException("Incorrect date format given. Must be \"yyyy.mm.dd\"");
        }

        /*
        for(int j = 0; j < datecomps.length; j++) {
            for (int i = 0; i < datecomps[j].length(); i++) {
                if (Character.digit(datecomps[j].charAt(i), 10) >= 0) {
                    continue;
                } else {
                    throw new NumberFormatException("Date component \"" + datecomps[j] + "\" is not an Int");
                }
            }
        }
        */

        try {
            DateFormat format = new SimpleDateFormat(DATEFORMAT, Locale.ENGLISH);
            this.recordDate = format.parse(rdate);
        } catch (IllegalArgumentException | ParseException e ){
            System.out.println("Incorrect date format given. Must be '" + DATEFORMAT + "'");
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    public String getPatientString(){
        StringBuffer sb = new StringBuffer();
        DateFormat dateFormat = new SimpleDateFormat(DATEFORMAT);
        String datestring = dateFormat.format(this.recordDate);

        sb.append(this.firstName);
        sb.append(" ");
        sb.append(this.lastName);
        sb.append(" ");
        sb.append(datestring);
        sb.append(" ");
        sb.append(this.SSnum);
        sb.append(" ");
        sb.append(this.disease);
        sb.append(" ");
        sb.append(this.cure);
        sb.append(" ");
        sb.append(this.Rx);

        return sb.toString();

    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public String getRecordDate() {
        return recordDate.toString();
    }

    public String getCure() {
        return cure;
    }

    public String getDisease() {
        return disease;
    }

    public String getRx() {
        return Rx;
    }

    public String getSSnum() {
        return SSnum;
    }

}

// Colleciton of methods to help with key mangament and signing.
class SecurityHelper{
    // Most of this code is taken from the Oracle: https://docs.oracle.com/javase/tutorial/security/apisign/step2.html
    public static KeyPair genKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        keyGen.initialize(1024, random);
        KeyPair pair = keyGen.generateKeyPair();

        return pair;
    }

    // Most of this code taken from Oracle: https://docs.oracle.com/javase/tutorial/security/apisign/step3.html
    // This method signs data. Of note signing hashes the data and then signs the hash that is appended to the data.
    // it takes a byte array.
    public static byte[] signData(byte[] data, PrivateKey privatekey)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException{
        Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
        dsa.initSign(privatekey);
        dsa.update(data);
        byte[] digSig = dsa.sign();

        return digSig;
    }

    //Much of this code taken from Oracle:
    //https://docs.oracle.com/javase/tutorial/security/apisign/examples/VerSig.java
    public static boolean verifySignedData(PublicKey pubkey, byte[] sig, byte[] data)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException{
        Signature signer = Signature.getInstance("SHA1withDSA", "SUN");
        signer.initVerify(pubkey);
        signer.update(data);
        return signer.verify(sig);
    }

    public static PublicKey getPubKeyEncoded(byte[] bpubkey)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(bpubkey);
        KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
        return pubKey;
    }

    public static String base64EncodeBytes(byte[] data){
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] base64DecodeString(String encodeddata){
        return Base64.getDecoder().decode(encodeddata);
    }

}

// Dedicated class for the Blockchain coordination.
// Most of the funcational relevant code is here.
class BCExecutor{
    int servermode;

    public static final int VERBOSE = 1;  // if verbose = 1 server will print more output
    public static final int difficulty = 22;

    // store local copies of the ports for easy reference.
    int keyport;
    int UVBport;
    int BCport;
    int q_len;

    //int worker_type; // 0 = BlockChain ; 1 = Unverified Blocks; 2 = Public Key
    int pid;


    BCstruct BC; // The blockchain that we are working on.
    String Lfilename; // The ledger filename that this process will be reading its data from.
    BCPeer[] neighs; // the list of neighbors
    KeyPair mykey; // the private/public keypair for this server.

    // Process from oldest to newest to minimize discards and implement FIFO.
    final PriorityBlockingQueue<BlockRecord> UVBqueue =
            new PriorityBlockingQueue<>(100, Collections.reverseOrder(new BlockRecordComparator()));;


    // Constructor: Initialize the server socket.
    BCExecutor(int basekeyport, int baseUBport, int baseBCport, int q_len, int pid, int servermode) throws NoSuchProviderException, NoSuchAlgorithmException {
        this.keyport = basekeyport + pid;
        this.UVBport = baseUBport + pid;
        this.BCport = baseBCport + pid;
        this.q_len = q_len;

        this.pid = pid;

        this.BC = new BCstruct(0);

        this.Lfilename = "BlockInput" + pid + ".txt";
        this.neighs = new BCPeer[3];

        this.mykey = SecurityHelper.genKeyPair();

        this.servermode = servermode;
        initializeNeighbors();
    }

    // initalize the peer group values. Note that this is hard coded to localhost
    // and the ports follow the given assignment parameters.
    private void initializeNeighbors(){
        for (int i = 0; i < this.neighs.length; i++){
            int li = i + 1;
            this.neighs[i] = new BCPeer();
            this.neighs[i].hostname = "localhost";
            this.neighs[i].ID = li;
            this.neighs[i].keyport = this.keyport - this.pid + i;
            this.neighs[i].UVBport = this.UVBport - this.pid + i;
            this.neighs[i].BCport = this.BCport - this.pid + i;
            //this.neighs[i].pubKey
        }
    }

    // Here we create a "less than" effect.
    // the lower the difficulty the harder the problem
    // difficulty: range(1 - 63). THIS DOESN't YET WORK.
    public void doWork1(int dif){
        int base_bytes = 8;
        byte[] nonce = new byte[16];
        SecureRandom random = new SecureRandom();

        random.nextBytes(nonce);

        BigInteger min_val = BigInteger.valueOf(2);
        min_val.pow(dif);


    }


    // Here int difficulty is the number of leading zeros
    // the higher the difficulty the harder the problem
    // difficulty: range(1 - 256) but never use 256 ...
    public boolean doWork2(int dif, BlockRecord newblock, boolean runslow){
        byte[] nonce = new byte[16];
        String hash;
        SecureRandom random = new SecureRandom();

        int counter = 0;
        long fullcounter = 0;


        long intcomp = 1;

        while(intcomp != 0) {
            random.nextBytes(nonce);
            newblock.setNonce(BlockRecord.byteToHexString(nonce));
            //newblock.resetTimestamp();

            hash = newblock.createBlockRecordHash();
            intcomp = Long.parseLong(hash.substring(0,15), 16);
            intcomp = intcomp << 4;

            long mask = 0xFFFFFFFFFFFFFFFFL;
            mask = mask >>> (64 - dif);
            mask = mask << (64 - dif);

            //System.out.println(String.format("%64s", Long.toBinaryString(intcomp)).replace(" ", "0"));
            //System.out.println(Long.toBinaryString(mask));

            intcomp = intcomp & mask;

            //System.out.println(hash);
            //System.out.println(intcomp);
            //System.out.println(Integer.toBinaryString(intcomp));
            counter++;

            if (runslow) {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    System.out.println("Interrupted: " + e.getMessage());
                    Thread.currentThread().interrupt();
                }
                counter = counter * 100000;
            }

            if (counter > 500000){
                if(!this.BC.checkPreviousHashMatch(newblock)){
                    System.out.println("Stop Work: Block has already been validated or is now invalid");
                    return false;
                }
                fullcounter += counter;
                counter = 0;
            }
        }

        fullcounter += counter;
        System.out.println("Work took  " + fullcounter + "  Hashes!!");
        return true;

    }

    // This function can validate that a node completed the had work (proof-of-work)
    // as the hash must mach the problem.
    public static boolean verifyWork2(int dif, BlockRecord newblock){
        String hash;
        long intcomp;

        hash = newblock.createBlockRecordHash();


        intcomp = Long.parseLong(hash.substring(0,15), 16);
        intcomp = intcomp << 4;

        long mask = 0xFFFFFFFFFFFFFFFFL;
        mask = mask >>> (64 - dif);
        mask = mask << (64 - dif);

        intcomp = intcomp & mask;

        if(intcomp == 0){
            return  true;
        } else {
            return false;
        }

    }

    void startUVBProcessor(){
        try {
            new Thread(new QueueProcessor(this)).start();
        } catch (IOException e){
            System.out.println("ERROR: Failed to start Processor");
        }
    }

    void processLocalPatientLedger(){
        String[] records;
        try {
            records = IOHelper.readRecordsFile(Lfilename);
        } catch(IOException e){
            System.out.println("Error reading file: " + Lfilename);
            e.printStackTrace();
            return;
        }

        int i = 0;
        int isnew = 1;
        BlockRecord newblock;
        UUID uuid = UUID.randomUUID();
        while (i < records.length){
            //System.out.println(records[i]);

            // if we move to the next record then get a new UUID otherwise continue with the same one.
            /*
            if(isnew == 1) {
                uuid = UUID.randomUUID();
                isnew = 0;
            }

             */
            int seq = this.pid *100 + i + 1;

            String prevHash = BC.getLastestBlock().createBlockRecordHash();
            //System.out.println( BC.getLastestBlock().getBlockID());
            newblock = new BlockRecord(records[i], prevHash, pid, uuid, seq);
            try {
                newblock.signBlockData(this.mykey.getPrivate());
            } catch (Exception e){
                System.out.println(e.getMessage());
                continue;
            }

            //System.out.println(doWork2(difficulty, newblock, false));
            //System.out.println(newblock.createBlockRecordHash());
            //System.out.println("VERIFYING WORK: " + verifyWork2(difficulty, newblock));
            try {
                broadcastUVB(newblock);
            } catch (Exception e){
                System.out.println("Error: failed to broadcast new UVB block");
                e.printStackTrace();
            }

            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                System.out.println("Interrupted: " + e.getMessage());
                Thread.currentThread().interrupt();
            }

            if(BC.findBLockSeq(seq) ){
                //retry the record
                i++;
                //isnew = 1;
            }
            //BC.addRecord(newblock);
            //myBC.printBC();
        }

        /*
        BlockRecord br;
        while((br = this.UVBqueue.poll()) != null){
            System.out.println(doWork2(difficulty, br, false));
            BC.addRecord(br);

        }

         */

        //String bcjsonstring = IOHelper.getJSONFromObject(BC);
        //System.out.println(bcjsonstring);
        //BCstruct myBC2 = IOHelper.getObjectFromJSON(bcjsonstring, BCstruct.class);

        try {
            broadcastBC();
        } catch (Exception e){
            System.out.println("ERROR: failed to multicast blockchain");
            e.printStackTrace();
        }

        // Sleep XX seconds before writing blockchain to console as peer updates may still be coming in.
        try {
            Thread.sleep(60000);
        } catch (InterruptedException e) {
            System.out.println("Interrupted: " + e.getMessage());
            Thread.currentThread().interrupt();
        }

        this.BC.printBC();

        // Sleep additional XX seconds before writing blockchain to JSON file.
        try {
            Thread.sleep(30000);
        } catch (InterruptedException e) {
            System.out.println("Interrupted: " + e.getMessage());
            Thread.currentThread().interrupt();
        }

        if(this.pid == 0) {
            IOHelper.writeStringToFile("BlockchainLedger.json", IOHelper.getJSONFromObject(this.BC));
        }

        goInteractive();
    }

    void goInteractive(){
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        try {
            String readline;
            int exitloop = 0;
            while (exitloop == 0){
                System.out.print("Select: \"V - to verify the blockchain\"," +
                        "\n \" R - to read in a new records file\" \n" +
                        "L - to print the blockchain \n" +
                        "or quit: ");
                System.out.flush (); // Why? System.out flushes on newline so this shouldn't be necessary
                readline = in.readLine ();

                String instruction = readline.replaceAll("\\s", "").toLowerCase();
                // "indexOf" can get a value anywhere in the string so that was removed.
                switch (instruction){
                    case "quit":
                        exitloop = 1;
                        break;
                    case "v":
                        this.BC.validateVerboseBC();
                        break;
                    case "r":
                        System.out.print("Enter your filename:  ");
                        System.out.flush (); // Why? System.out flushes on newline so this shouldn't be necessary
                        readline = in.readLine ();
                        this.Lfilename = readline;
                        processLocalPatientLedger();
                        break;
                    case "l":
                        this.BC.printBC();
                    default:
                        System.out.println("Input \"" + instruction + "\" was not recognized");

                }

            }
            System.out.println ("Cancelled by user request.");
        } catch (IOException x) {x.printStackTrace ();}
    }

    void broadcastBC(){
        Socket sock;
        PrintStream out;

        String bcjsonstring = IOHelper.getJSONFromObject(BC);

        //SecurityHelper.signData(bcjsonstring.getBytes(StandardCharsets.UTF_8), this.mykey.getPrivate());

        broadcastHelper(bcjsonstring, 1);

    }

    void broadcastUVB(BlockRecord newblock) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        Socket sock;
        PrintStream out;

        //SecurityHelper.verifySignedData(pubket, sig, data);

        String jsonUVB = IOHelper.getJSONFromObject(newblock);
        byte[] sig = SecurityHelper.signData(jsonUVB.getBytes(StandardCharsets.UTF_8), this.mykey.getPrivate());
        String base64sig = SecurityHelper.base64EncodeBytes(sig);

        EncodedUVBStruct encUVB = new EncodedUVBStruct(jsonUVB, base64sig, this.pid);

        String jsonMessage = IOHelper.getJSONFromObject(encUVB);
        //SecurityHelper.signData(bcjsonstring.getBytes(StandardCharsets.UTF_8), this.mykey.getPrivate());

        broadcastHelper(jsonMessage, 2);

    }

    // type: 0 = key, 1 = BC, 2 = UVB
    private void broadcastHelper(String message, int type){
        Socket sock;
        PrintStream out;


        for (int i = 0; i < neighs.length; i++) {
            try {
                int port;
                if(type == 0){
                    port = neighs[i].keyport;
                } else if(type == 1) {
                    port = neighs[i].BCport;
                }else if(type == 2){
                    port = neighs[i].UVBport;
                }else {
                    System.out.println("ERROR: invalid type in broadcastHelper");
                    break;
                }
                //System.out.println("Trying to connect to: " + neighs[i].hostname + ":" + port);
                sock = new Socket(neighs[i].hostname, port);
                out = new PrintStream(sock.getOutputStream());
                out.print(message);
                out.flush();
                sock.close();

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    void broadcastPublicKey(){
        Socket sock;
        PrintStream out;

        String myEncodedPubKey = SecurityHelper.base64EncodeBytes(this.mykey.getPublic().getEncoded());

        EncodedPubKeyStruct skey = new EncodedPubKeyStruct(myEncodedPubKey, this.pid);

        String message = IOHelper.getJSONFromObject(skey);

        broadcastHelper(message, 0);
    }

    void startListeners(){
        int[] ports = new int[]{this.BCport, this.UVBport, this.keyport};
        for(int i = 0; i < 3; i++){
            try {
                new Thread(new GenericListener(ports[i], this.q_len, this, i)).start();
            } catch (IOException e){
                System.out.println("ERROR: Failed to start listeners");
                break;
            }
        }
    }
    class QueueProcessor implements Runnable{
        // listen for a new connection. If one is received hand of the socket
        // to a new thread in WebWorker.
        BCExecutor bce;

        QueueProcessor(BCExecutor bce) throws IOException{
            this.bce = bce;
        }

        public void listen(){
            while(true) {
                BlockRecord br;
                try {
                    br = bce.UVBqueue.take();
                    System.out.println("Processing new UVB from queue");
                } catch (InterruptedException e) {
                    e.printStackTrace();
                    break;
                }

                //validate data signature
                int owner;
                if(br.userID.equals("PID0")){
                    owner = 0;
                }else if(br.userID.equals("PID1")){
                    owner = 1;
                }else if(br.userID.equals("PID2")){
                    owner = 2;
                } else {
                    System.out.println("ERROR: Could not find valid owner: " + br.userID);
                    continue;
                }

                // Verify the data signature, then the previous HAsh. If both ok verify (doWork).
                try{
                    if(SecurityHelper.verifySignedData(bce.neighs[owner].pubKey, br.getDataSig(), br.patientData.getPatientString().getBytes(StandardCharsets.UTF_8))){
                        if(bce.BC.checkPreviousHashMatch(br)) {
                            if(bce.doWork2(BCExecutor.difficulty, br, false)) {
                                if (bce.BC.addRecord(br, bce.pid)) {
                                    bce.broadcastBC();
                                }
                            }
                        } else {
                            System.out.println("Discarding UVB, hash doesn't match previous hash");
                        }
                    }
                } catch (Exception e){
                    System.out.println(e.getMessage());
                    e.printStackTrace();
                }

            }
        }

        public void run(){
            listen();
        }


    }


    class GenericListener implements Runnable{
        // listen for a new connection. If one is received hand of the socket
        // to a new thread in WebWorker.
        ServerSocket servsock;
        BCExecutor bce;
        int worker_type; // 0 = BlockChain ; 1 = Unverified Blocks; 2 = Public Key

        GenericListener(int port, int q_len, BCExecutor bce, int wtype) throws IOException{

            this.bce = bce;
            this.worker_type = wtype;

            // ServerSocket is essentially the "LISTEN" type port.
            try {
                this.servsock = new ServerSocket(port, q_len);
            } catch (IOException e) {
                System.err.println(e);
                throw new IOException ("Error: couldn't create listener socket");
            }


        }

        public void listen(){
            try {
                Socket sock;
                if(worker_type == 0) {
                    System.out.println("Starting BlockChain Listener on port: " + servsock.getLocalPort());
                    while (true) {
                        sock = servsock.accept();
                        new Thread(new BCWorker(sock, this.bce)).start();
                    }
                } else if (worker_type == 1){
                    System.out.println("Starting UVB Listener on port: " + servsock.getLocalPort());
                    while (true) {
                        sock = servsock.accept();
                        new Thread(new UVBWorker(sock, this.bce)).start();
                    }
                } else if (worker_type == 2){
                    System.out.println("Starting Key Listener on port: " + servsock.getLocalPort());
                    while (true) {
                        sock = servsock.accept();
                        new Thread(new KeyWorker(sock, this.bce)).start();
                    }
                } else {
                    System.out.println("ERROR: Worker type specified is invalid ");
                }
            } catch (IOException e) {
                System.err.println(e);
            }
        }

        public void run(){
            listen();
        }


    }

    static class KeyWorker implements Runnable {

        Socket sock;
        BCExecutor bce;

        // constructor: requires a socket and listener object to instantiate this object.
        KeyWorker(Socket sock, BCExecutor listener) {
            this.sock = sock;
            this.bce = listener;
        }

        public void run() {

            PrintStream out;
            BufferedReader in;

            StringBuffer request; //the raw input

            try {
                //out = new PrintStream(sock.getOutputStream());
                in = new BufferedReader(new InputStreamReader(sock.getInputStream()));

                request = new StringBuffer();

                int br = 0;

                String textFromServer;
                // Read a single line, then enter a while loop to received the entire data
                textFromServer = in.readLine();
                while (textFromServer != null && br < 1000) {
                    //System.out.println(textFromServer);
                    if (textFromServer.isEmpty()) {
                        break;
                    }
                    request.append(textFromServer);
                    br++;
                    // read a new line prior to the next loop.
                    textFromServer = in.readLine();
                }
            } catch (IOException x) {
                System.out.println("Error: Connetion reset. Listening again..." + "\n" + x.getMessage());
                return;
            }

            //System.out.println(request.toString());

            EncodedPubKeyStruct rcvkey = IOHelper.getObjectFromJSON(request.toString(), EncodedPubKeyStruct.class);
            int rcvpid;
            try {
                rcvpid = Integer.parseInt(rcvkey.pid);
                if (rcvpid != 0 && rcvpid != 1 && rcvpid != 2 ) {
                    System.out.println("ERROR: Received PID is not valid: " + rcvkey.pid);
                }
            } catch (NumberFormatException e) {
                System.out.println("ERROR: Received PID is not valid: " + rcvkey.pid);
                return;
            }

            try {
                bce.neighs[rcvpid].pubKey = SecurityHelper.getPubKeyEncoded(SecurityHelper.base64DecodeString(rcvkey.encodedpubkey));
            } catch (Exception e){
                System.out.println("Error: failed to retrieve public key from network");
                e.printStackTrace();
            }

            System.out.println("Received public key from Process: " + rcvpid);
            System.out.println(SecurityHelper.base64EncodeBytes(bce.neighs[rcvpid].pubKey.getEncoded()));

            if(bce.servermode == 1 && rcvpid == 2){
                if (bce.pid != 2) {
                    bce.broadcastPublicKey();
                }
                bce.startUVBProcessor();
                bce.processLocalPatientLedger();
            }

        }
    }

    // BCWorker - class to process full blockchain update requests.
    // receives a blockchain and validates it on length (must be longer)
    // and validity (consistency per class BCStruct)
    static class BCWorker implements Runnable {

        Socket sock;
        BCExecutor bce;

        // constructor: requires a socket and listener object to instantiate this object.
        BCWorker(Socket sock, BCExecutor listener) {
            this.sock = sock;
            this.bce = listener;
        }

        public void run() {

            //PrintStream out;
            BufferedReader in;

            StringBuffer request; //the raw input

            try {
                //out = new PrintStream(sock.getOutputStream());
                in = new BufferedReader(new InputStreamReader(sock.getInputStream()));

                request = new StringBuffer();

                int br = 0;

                String textFromServer;
                // Read a single line, then enter a while loop to received the entire data
                textFromServer = in.readLine();
                while (textFromServer != null && br < 1000) {
                    //System.out.println(textFromServer);
                    if (textFromServer.isEmpty()) {
                        break;
                    }
                    request.append(textFromServer);
                    br++;
                    // read a new line prior to the next loop.
                    textFromServer = in.readLine();
                }
            } catch (IOException x) {
                System.out.println("Error: Connetion reset. Listening again..." + "\n" + x.getMessage());
                return;
            }

            //System.out.println(request.toString());

            BCstruct newBC = IOHelper.getObjectFromJSON(request.toString(), BCstruct.class);


            if(newBC.getLength() > this.bce.BC.getLength()){
                if (newBC.validateBC()) {
                    this.bce.BC = newBC;
                    System.out.println("Received updated BC: Replacing local BC");
                } else {
                    System.out.println("Received updated BC: Rejecting it as invalid");
                }
            } else {
                System.out.println("Received updated BC: Rejecting as not long enough");
            }



        }
    }
    static class UVBWorker implements Runnable {

        Socket sock;
        BCExecutor bce;

        // constructor: requires a socket and listener object to instantiate this object.
        UVBWorker(Socket sock, BCExecutor listener) {
            this.sock = sock;
            this.bce = listener;
        }

        public void run() {

            //PrintStream out;
            BufferedReader in;

            StringBuffer request; //the raw input

            try {
                //out = new PrintStream(sock.getOutputStream());
                in = new BufferedReader(new InputStreamReader(sock.getInputStream()));

                request = new StringBuffer();

                int br = 0;

                String textFromServer;
                // Read a single line, then enter a while loop to received the entire data
                textFromServer = in.readLine();
                while (textFromServer != null && br < 1000) {
                    //System.out.println(textFromServer);
                    if (textFromServer.isEmpty()) {
                        break;
                    }
                    request.append(textFromServer);
                    br++;
                    // read a new line prior to the next loop.
                    textFromServer = in.readLine();
                }
            } catch (IOException x) {
                System.out.println("Error: Connetion reset. Listening again..." + "\n" + x.getMessage());
                return;
            }

            //System.out.println(request.toString());

            EncodedUVBStruct newUVB = IOHelper.getObjectFromJSON(request.toString(), EncodedUVBStruct.class);
            int rcvpid;
            try {
                rcvpid = Integer.parseInt(newUVB.pid);
                if (rcvpid != 0 && rcvpid != 1 && rcvpid != 2 ) {
                    System.out.println("ERROR: Received PID is not valid: " + newUVB.pid);
                }
            } catch (NumberFormatException e) {
                System.out.println("ERROR: Received PID is not valid: " + newUVB.pid);
                return;
            }

            byte[] newsig;
            try {
                newsig = SecurityHelper.base64DecodeString(newUVB.encodedSig);
            } catch (Exception e){
                System.out.println("Error: failed to retrieve signed UVB from network");
                e.printStackTrace();
                return;
            }
            try {
                if(SecurityHelper.verifySignedData(bce.neighs[rcvpid].pubKey, newsig, newUVB.jsonUVB.getBytes(StandardCharsets.UTF_8))){
                    System.out.println("Received valid UVB block, adding to priority queue. From PID" + rcvpid);
                    BlockRecord newbr = IOHelper.getObjectFromJSON(newUVB.jsonUVB, BlockRecord.class);
                    bce.UVBqueue.add(newbr);
                } else {
                    System.out.println("Signature of UVB block invalid, from PID " + rcvpid);
                }
            } catch (Exception e){
                System.out.println("Error: exception while verifying or adding singed UVB from network");
                e.printStackTrace();
                return;
            }



        }
    }
}

