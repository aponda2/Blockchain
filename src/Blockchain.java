/*--------------------------------------------------------

1. Paul Ponda / Date: 01/17/2021

2. Java version used, if not the official version for the class:
both of:
openjdk 9
openjdk 11.0.9 2020-10-20 LTS



3. Precise command-line compilation examples / instructions:
javac *.java


4. Precise examples / instructions to run this program:

e.g.:

In separate shell windows:

> java JokeServer
> java JokeClient
> java JokeClientAdmin

All acceptable commands are displayed on the various consoles.

5. List of files needed for running the program.

 a. checklist.html
 b. JokeServer.java
 c. JokeClient.java
 d. JokeClientAdmin.java

5. Notes:

e.g.:

I ran out of time so haven't completely tested the input/output features. The client does work
with multiple servers and parses that on the command line but not perfectly per the documentaiton description.

----------------------------------------------------------*/

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

public class Blockchain {
    private int serverMode = 0;


    public static void main(String args[]) throws IOException, IllegalArgumentException {
        int q_len = 6;
        int basekeyport = 4710;
        int baseUBport = 4820;
        int baseBCport = 4930;

        int PID;

        IOHelper myIOutil = new IOHelper();
        // Command line allows reading a custom port number to listen on.

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

        // Start the blockchain executor which handles BLockChain and the listeners.
        BCExecutor bce;
        try {
            bce = new BCExecutor(basekeyport, baseUBport, baseBCport, q_len, PID);
        } catch (Exception e){
            System.out.println("ERROR: " + e.getMessage());
            return;
        }

        bce.startListeners();
        try{ Thread.sleep(5000);} catch(InterruptedException e)
        {
            System.out.println("Interrupted: " + e.getMessage());
            Thread.currentThread().interrupt();
        }

        //bce.processLocalPatientLedger();

        KeyPair mykey;
        byte[] sig;
        try {
            mykey = SecurityHelper.genKeyPair();
            sig = SecurityHelper.signData(bce.BC.getLastestBlock().patientData.getPatientString().getBytes(StandardCharsets.UTF_8),
                    mykey.getPrivate());

            //String temp = new String(sig, StandardCharsets.UTF_8);
            //System.out.println(temp);
            System.out.println(SecurityHelper.base64EncodeBytes(sig));

            String encodedpub = SecurityHelper.base64EncodeBytes(mykey.getPublic().getEncoded());

            PublicKey decodedpub = SecurityHelper.getPubKeyEncoded(SecurityHelper.base64DecodeString(encodedpub));

            boolean test = SecurityHelper.verifySignedData(decodedpub, sig,
                    bce.BC.getLastestBlock().patientData.getPatientString().getBytes(StandardCharsets.UTF_8));

            System.out.println(test);
        } catch (Exception e){
            System.out.println(e.getMessage());
        }


        bce.broadcastHello();
        /*
        // Print all of the providers supported on this system.
        for(int i = 0; i<Security.getProviders().length; i++) {
            System.out.println(Security.getProviders()[i].toString());
        }
        */

        //final PriorityBlockingQueue<BlockRecord> ourPriorityQueue = new PriorityBlockingQueue<>(100);
    }

}
class BCPeer{
  int ID;
  PublicKey pubKey;
  int port;
  String hostname;
}

class BCstruct{
    LinkedList<BlockRecord> recordList;

    // Initiate a new BlockChain
    BCstruct(int uid) {
        recordList = new LinkedList<BlockRecord>();

        try {
            recordList.add(new BlockRecord(uid));
        } catch (NoSuchAlgorithmException e){
            System.out.println("ERROR: Could not initialize blockchain first record.");
        }
    }

    public BlockRecord getLastestBlock(){
        return recordList.getFirst();
    }

    public void addRecord(BlockRecord br){

        // If this is the first block.
        if(this.recordList.size() == 0) {
            this.recordList.addFirst(br);
        } else {
            // Check that prevHash matches
            if (br.previousHash.equals(this.getLastestBlock().createBlockRecordHash())){
                System.out.println("SUCCESS ADDING BLOCK");
                this.recordList.addFirst(br);
            } else {
                System.out.println("FAILED ADDING BLOCK");
                System.out.print(br.previousHash);
                System.out.print(" != ");
                System.out.print(this.getLastestBlock().createBlockRecordHash());
                System.out.print("\n");

            }
        }
    }

    public void printBC(){

        System.out.println("#### START PRINTING BlockChain ####");
        for(int i = 0; i< recordList.size(); i++){
            System.out.println(" Record #: " + i);
            recordList.get(i).printBlockRecord();
            System.out.println("");
        }
        System.out.println("#### END PRINTING BlockChain ####\n");
    }

}
class BlockRecord implements Serializable{
    private final String DATEFORMAT = "yyyy-MM-dd.HH:mm:ss.S";
    private final int NONCE_LEN = 2; //in bytes
    private final String HASH_TYPE = "SHA-256";

    UUID BlockID;
    byte[] Nonce;
    String previousHash;
    PatientRecord patientData;
    String timestamp;
    String userID;

    BlockRecord(String patStr, String prevH, int uid){
        this.previousHash = prevH;
        this.BlockID = UUID.randomUUID();
        this.Nonce = new byte[NONCE_LEN];
        new Random().nextBytes(this.Nonce);
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

    }

    //Initializes a null record (first record)
    BlockRecord(int uid) throws NoSuchAlgorithmException {
        this("Jane Doe 1900.01.01 000-00-0000 NA NA NA",
                "0000000000000000000000000000000000000000000000000000000000000000", uid);

        //this.previousHash = this.genBaseHash(algo);
    }

    public void printBlockRecord(){
        System.out.println(" *** Printing Block ***");
        System.out.println("BLOCK ID: " + this.BlockID.toString());
        System.out.println("Previous Hash: " + this.previousHash);
        System.out.println("Time Stamp: " + this.timestamp);
        System.out.println("Owner: " + this.userID);
        System.out.println("Data: " + this.patientData.getPatientString());
        System.out.println(" *** End Block ***");
    }

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

    private static String byteToHexString(byte[] mySHA) {
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
        //MISSING PROCESS ID
        sb.append(timestamp);

        byte[] sbbyte = sb.toString().getBytes(StandardCharsets.US_ASCII);
        byte[] databyte = patientData.getPatientString().getBytes(StandardCharsets.US_ASCII);

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

    public String getNonceToHexString(byte[] buff){
        return byteToHexString(buff);
    }

    public String getBlockID(){
        return BlockID.toString();
    }

    public UUID getBlockIDObj(){
        return this.BlockID;
    }

    public byte[] getNonce() {
        return this.Nonce;
    }

    public String getPreviousHash(){
        return this.previousHash;
    }


}
class IOHelper{
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

    static <T> String getJSONFromObject(T objectforJSON){

        Gson gson = new GsonBuilder().setPrettyPrinting().create();

        // Convert the passed object to JSON
        String jstring = gson.toJson(objectforJSON);


        return jstring;
    }

    static <T> T getObjectFromJSON(String jstr, Class<T> cls){

        Gson gson = new Gson();

        // Convert the passed string to object of given class.
        T jobj = gson.fromJson(jstr, cls);

        return jobj;
    }

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
// Dedicated class for the Blockhain Server Handler.
// Checks inital connection parameters and tracks a connection counter.
class BCExecutor{
    public static final int VERBOSE = 1;  // if verbose = 1 server will print more output

    int keyport;
    int UVBport;
    int BCport;
    int q_len;

    //int worker_type; // 0 = BlockChain ; 1 = Unverified Blocks; 2 = Public Key
    int pid;

    BCstruct BC;
    String Lfilename;
    // Initialize a basic neighbor structure.
    BCPeer[] neighs; // the list of neighbors
    KeyPair mykey; // the private/public keypair for this server.

    // Constructor: Initialize the server socket.
    BCExecutor(int basekeyport, int baseUBport, int baseBCport, int q_len, int pid) throws NoSuchProviderException, NoSuchAlgorithmException {
        this.keyport = basekeyport + pid;
        this.UVBport = baseUBport + pid;
        this.BCport = baseBCport + pid;
        this.q_len = q_len;

        this.pid = pid;

        this.BC = new BCstruct(0);

        this.Lfilename = "BlockInput" + pid + ".txt";
        this.neighs = new BCPeer[3];

        this.mykey = SecurityHelper.genKeyPair();

        initializeNeighbors();
    }

    private void initializeNeighbors(){
        for (int i = 0; i < this.neighs.length; i++){
            int li = i + 1;
            this.neighs[i] = new BCPeer();
            this.neighs[i].hostname = "localhost";
            this.neighs[i].ID = li;
            this.neighs[i].port = this.keyport - this.pid + i;
            //this.neighs[i].pubKey
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

        for (int i = 0; i < records.length; i++){
            System.out.println(records[i]);

            String prevHash = BC.getLastestBlock().createBlockRecordHash();
            System.out.println( BC.getLastestBlock().getBlockID());
            BlockRecord newblock = new BlockRecord(records[i], prevHash, pid );
            BC.addRecord(newblock);
            //myBC.printBC();
        }

        String bcjsonstring = IOHelper.getJSONFromObject(BC);
        System.out.println(bcjsonstring);
        BCstruct myBC2 = IOHelper.getObjectFromJSON(bcjsonstring, BCstruct.class);

        myBC2.printBC();
    }

    void broadcastHello(){
        Socket sock;
        PrintStream out;

        for (int i = 0; i < neighs.length; i++) {
            try {

                System.out.println("Trying to connect to: " + neighs[i].hostname + ":" + neighs[i].port);
                sock = new Socket(neighs[i].hostname, neighs[i].port);
                out = new PrintStream(sock.getOutputStream());
                out.println("Hello multicast message from process" + this.pid);
                out.flush();
                sock.close();

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
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
                        new Thread(new BlockChainWorker(sock, this.bce)).start();
                    }
                } else if (worker_type == 1){
                    System.out.println("Nothing here " + worker_type);
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
                out = new PrintStream(sock.getOutputStream());
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
                    request.append(textFromServer + "\n");
                    //request.append(br + ": " + textFromServer + "<br>\n");
                    br++;
                    // read a new line prior to the next loop.
                    textFromServer = in.readLine();
                }
            } catch (IOException x) {
                System.out.println("Error: Connetion reset. Listening again..." + "\n" + x.getMessage());
                return;

            }

            System.out.println(request.toString());
        }
    }

    static class BlockChainWorker implements Runnable{
        Socket sock;
        BCExecutor bce;

        // constructor: requires a socket and listener object to instantiate this object.
        BlockChainWorker(Socket sock, BCExecutor listener){
            this.sock = sock;
            this.bce = listener;
        }

        public void run() {
            PrintStream out;
            BufferedReader in;

            StringBuffer request; //the raw input

            try {
                out = new PrintStream(sock.getOutputStream());
                in = new BufferedReader(new InputStreamReader(sock.getInputStream()));

                request = new StringBuffer();

                int br = 0;
                String textFromServer;
                long startTime;

                // Read a single line, then enter a while loop to received the entire header
                textFromServer = in.readLine();
                //todo: Header must end with a blank line per RFC7230. If it doesn't this gets stuck
                // implement a ExecutorService that prevents this via a timeout.
                while (textFromServer != null && br < 1000) {
                    //System.out.println(textFromServer);
                    if (textFromServer.isEmpty()) {
                        break;
                    }
                    request.append(textFromServer + "\n");
                    //request.append(br + ": " + textFromServer + "<br>\n");
                    br++;
                    // read a new line prior to the next loop.
                    textFromServer = in.readLine();
                }
            } catch (IOException x) {
                System.out.println("Error: Connetion reset. Listening again..." + "\n" + x.getMessage());

            }
        }

        private void BCWorker(){
        }
    }
}

