/*--------------------------------------------------------

1. Paul Ponda / Date: 02/07/2021

2. Java version used, if not the official version for the class:
both of:
openjdk 9
openjdk 11.0.9 2020-10-20 LTS

3. Precise command-line compilation examples / instructions:
javac *.java


4. Precise examples / instructions to run this program:

Simply run
> java MiniWebserver <port>

5. List of files needed for running the program.
 a. MiniWebserver.java
 b. WebAdd.html

5. Notes:
In reponse to checklist questions:
- In my response header (server-side) I set the content-type to text/html. This is currently hard coded.
- If I wanted to I could set content-type to text/plain and that would let the client (browser) know to process the page
as text.
- I still want to add MIME type processing by file extension name such as image/jpeg for .jpg files; this is how the
web server can let the client know what type of data is coming. Furthermore we can see for example in firefox debug console
that the image request to website are separate GET requests therefore the server can set the MIME type values independently
for each of those.

----------------------------------------------------------*/


import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Date;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;

public class Blockchain {

    // Declare a few immmutable parameters values / settings for the server.
    public static final int Q_LEN = 6;
    public static final int SERVERPORT = 2540;
    public static final int VERBOSE = 0;  // if verbose = 1 server will print more output
    static int i = 0;

    // Main method of MiniWebServer
    public static void main(String args[]) throws IllegalArgumentException, IOException {
        int q_len = Q_LEN;
        int serverport = SERVERPORT;
        WebListener listener;

        // Command line allows reading a custom port number to listen on.
        switch (args.length) {
            case 0:
                break;
            case 1:
                for(int i = 0; i < args[0].length(); i++) {
                    if(Character.digit(args[0].charAt(i), 10) >= 0){
                        continue;
                    } else {
                        throw new IllegalArgumentException("Usage: Argument \"" + args[0] + "\" is not a valid Int") ;
                    }
                }

                try {
                    serverport = Integer.parseInt(args[0]);
                    if (serverport > 65535 || serverport < 1 ) {
                        System.out.println("Not a valid port number, must be in range 1 - 65535");
                        System.exit(1);
                    }
                } catch ( NumberFormatException e ){
                    System.out.println("Error occurred reading port");
                    throw new NumberFormatException(e.getMessage());
                }
                break;
            default:
                System.err.println("Usage: Passed too many arguments");
                System.exit(1);
        }

        System.out.println("Paul's MiniWeb server v0.1a starting up");
        System.out.println("Listening at port " + serverport + "\n");

        try {
            listener = new WebListener(serverport, q_len);
            listener.listen();
        } catch (IOException e){
            System.out.println("Error occurred starting server");
            throw new IOException(e.getMessage());
        }
    }
}

// Dedicated class for the Web Server Listener.
// Checks inital connection parameters and tracks a connection counter.
class WebListener {
    public static final int VERBOSE = 1;  // if verbose = 1 server will print more output
    ServerSocket servsock;
    int listen_counter; // track number of connection received.
    //private WebWorker worker;

    WebListener(ServerSocket servsock){
        this.servsock = servsock;
        listen_counter = 0;
    }
    WebListener(int port) throws IOException{
        this(port, 6);
    }

    // Constructor: Initialize the server socket.
    WebListener(int port, int q_len) throws IOException{
        // ServerSocket is essentially the "LISTEN" type port.
        try {
            this.servsock = new ServerSocket(port, q_len);
        } catch (IOException e) {
            System.err.println(e);
            throw new IOException ("Error: " + e.getMessage());
        }

        listen_counter = 0;
    }

    // listen for a new connection. If one is received hand of the socket
    // to a new thread in WebWorker.
    public void listen(){
        try {
            Socket sock;
            while (true) {
                sock = servsock.accept();
                new Thread(new WebWorker(sock, this)).start();

                // increment the number of connections received
                listen_counter++;
            }
        } catch (IOException e) {
            System.err.println(e);
        }
    }
}

// Worker class for handling the client connections
// since it implement runnable these methods could be called outside a thread as needed.
class WebWorker implements Runnable{
    Socket sock;
    WebListener listener;

    // constructor: requires a socket and listener object to instantiate this object.
    WebWorker(Socket sock, WebListener listener){
        this.sock = sock;
        this.listener = listener;
    }

    public void run(){
        PrintStream out;
        BufferedReader in;

        StringBuffer request; //the raw HTTP request header.
        RequestHTTPHeader hrequest; // object to hold the parse request
        ResponseHTTPHeader hreply; // object to hold a server reply.
        String body; // String containing the entire html body.

        System.out.println("Connection Received - Total Count: " + Integer.toString(listener.listen_counter) + "\n");
        try {
            out = new PrintStream(sock.getOutputStream());
            in = new BufferedReader(new InputStreamReader(sock.getInputStream()));

            request = new StringBuffer();

            int br = 0;
            int listentimer = 10000; //in milliseconds
            String textFromServer;
            long startTime;

            // Read a single line, then enter a while loop to received the entire header
            // until a blank line is received per RFC7230 indicating the request-header end.
            textFromServer = in.readLine();
            startTime = System.currentTimeMillis();
            //todo: Header must end with a blank line per RFC7230. If it doesn't this gets stuck
            // implement a ExecutorService that prevents this via a timeout.
            while (textFromServer != null && br < 1000){
                //System.out.println(textFromServer);
                if(textFromServer.isEmpty()){
                    break;
                }
                request.append(textFromServer + "\n");
                //request.append(br + ": " + textFromServer + "<br>\n");
                br++;
                // read a new line prior to the next loop.
                textFromServer = in.readLine();

                // This segment of code is trying to instantiate an executor to create
                // a timed request in case of a malformed header. Thread safety is a problem
                // here.
                /*
                if (System.currentTimeMillis() > startTime + listentimer){
                    System.out.println("Error: Took to long to read request. Breaking connection.");
                    sock.close();
                    return;
                }
                ExecutorService executor = Executors.newSingleThreadExecutor();
                tempreader = new TimedRead(in);
                new Thread(tempreader);
                textFromServer

                 */
            }
            //request.append("</html>\n");

            // This will print the received header
            if(WebListener.VERBOSE >= 1) {
                System.out.println(request.toString());
            }

            // Process the request-header method. If it is not a GET
            // reply to the webserver with a 405 code. Tested using telnet POST.
            hrequest = new RequestHTTPHeader(request);
            if(!hrequest.method.equals("GET")){
                hreply = new ResponseHTTPHeader(405, 0);
                out.println(hreply.getHeader());
                sock.close();
                System.out.println("Operation " + hrequest.method + " not supported");
                return;
            }

            // Process the "target" which is the location specified in the start line of the header
            try {
                //This was used to check the favicon.ico request from firefox but was replaced with the 404
                // error mode.
                /*
                if(!hrequest.target.equals("./favicon.ico")) {
                    if (hrequest.target.equals("./WebAdd.fake-cgi")){
                        body = processWebFakeCGI(hrequest.target_params, false);
                    } else {
                        body = readHTML(hrequest.target);
                    }
                } else {
                    return;
                }
                 */


                // There are two options: If the CGI file is requested specifically by name.
                // then it will process it and return the value.
                // If it was anythine else it treats is as a HTML filename and fill try to open
                // it in method readHTML
                // todo: if the file is anything but an HTML file this will exhibit incorrect behavior
                //  not setting the correct MIME types. Create a wrapper that parses these headers
                //  by file extensions.
                if (hrequest.target.equals("./WebAdd.fake-cgi")){
                    body = processWebFakeCGI(hrequest.target_params, false);
                } else {
                    body = readHTML(hrequest.target);
                }

            } catch (FileNotFoundException e){
                hreply = new ResponseHTTPHeader(404, 0);
                out.println(hreply.getHeader());
                sock.close();
                System.out.println("Requested File " + hrequest.target + " not found");
                return;
            } catch (IOException e) {
                sock.close();
                throw new IOException("Error reading file: " + hrequest.target);
            }


            // Initialize the "200 OK" header reply. For this simple web server
            // most of the header values are presets.
            hreply = new ResponseHTTPHeader(200, body.length());

            // Finally send the header and then the payload to the client browser.
            out.println(hreply.getHeader());
            out.println(body);

            sock.close(); // close this connection, but not the server;
        } catch (IOException x) {
            System.out.println("Error: Connetion reset. Listening again..." + "\n" + x.getMessage());
        }
    }

    // Never used - this is code to eventually properly process the request header and to not
    // get stuck if malformed.
    class TimedRead implements Runnable {
        BufferedReader queue;
        private StringBuffer stringout;

        public void run(){
            try {
                this.stringout.append(this.queue.readLine());
            } catch (IOException e) {
                System.out.println("Error reading buffer: " + e.getMessage());
            }
        }

        TimedRead(BufferedReader queue){
            this.queue = queue;
            this.stringout = new StringBuffer();
        }

        String getString(){
            return this.stringout.toString();
        }
    }

    // Read an HTML file as text and return it in a String object.
    String readHTML(String filename) throws FileNotFoundException, IOException{
        StringBuilder sb = new StringBuilder();

        BufferedReader reader = new BufferedReader(new FileReader(filename));

        String nextline = reader.readLine();
        while (nextline != null) {
            sb.append(nextline + "\n");
            nextline = reader.readLine();
        }
        reader.close();

        return sb.toString();
    }

    // Process the CGI request.
    // Inputs:
    //  params - this are all values after the "?" in the HTTP GET request.
    //  newpage - this flag can be used to create a new page instead of reading WebAdd.html.
    String processWebFakeCGI(String params, boolean newpage) throws FileNotFoundException, IOException{
        String[] values = params.split("&");
        String[][] valmap = new String[values.length][2];
        StringBuilder html_response = new StringBuilder();

        //System.out.println(params);
        String person = "";
        int num1 = 0;
        int num2 = 0;

        // Create a key:value map using a simple String array.
        // if any value is blank this will cause the server to return an error page.
        // todo: handle this better by returning an error 500 or reloading WebAdd.html with an
        //  error message.
        for(int i = 0; i< values.length; i++){
            String[] tempsplit = values[i].split("=");
            if(tempsplit.length != 2){
                System.out.println("Error: invalid CGI parameters");
                return "Error: invalid CGI parameters";
            }
            valmap[i][0] = tempsplit[0];
            valmap[i][1] = tempsplit[1];
        }


        // process the valmap for each parameters in it.
        // theoretically there are only 3 parameters to set here and all must be set.
        // the default ignores any mismatched parameters to be handled in later
        // error checking.
        for(int i = 0; i< values.length; i++){
            switch (valmap[i][0]){
                case "person":
                    person = valmap[i][1];
                    person = person.replaceAll("\\+", " ");
                    break;
                case "num1":
                    try {
                        num1 = Integer.parseInt(valmap[i][1]);
                    } catch (NumberFormatException e){
                        return "First number provide is not a valid number";
                    }
                    break;
                case "num2":
                    try {
                        num2 = Integer.parseInt(valmap[i][1]);
                    } catch (NumberFormatException e){
                        return "Second number provide is not a valid number";
                    }
                    break;
                default:

            }
        }

        if(person == ""){
            return "No name or values error";
        }

        int sumval = num1 + num2;

        // Create the body of the message which is the HTML document.
        // if newpage == false then this will first read the WebAdd.html file.
        // look for the "</BODY>" tag an insert the reply before this tag.
        if(newpage) {
            html_response.append("<!DOCTYPE html>\n<html>\n");
            html_response.append("<head>\n<title> Paul's CGI results!</title></head>");
            html_response.append("<body>\n");
            html_response.append("<h2> Paul's CGI results!</h2>\n");
            html_response.append("<strong>Your name is:  </strong>" + person + "<br>\n");
            html_response.append("<strong>The sum is:  </strong>" + String.valueOf(sumval) + "<br>\n");
            html_response.append("Thank you for trying this form.<br>\n");
            html_response.append("</body>\n</html>\n");
        } else {
            StringBuilder tempsb = new StringBuilder();
            html_response.append(readHTML("./WebAdd.html"));
            int idx;
            idx = html_response.indexOf("</BODY>");
            if (idx == -1){
                return "Error: </BODY> was not found in WebAdd.html";
            }
            tempsb.append("\n");
            tempsb.append("<h2> Paul's CGI results!</h2>\n");
            tempsb.append("<strong>Your name is:  </strong>" + person + "<br>\n");
            tempsb.append("<strong>The sum is:  </strong>" + String.valueOf(sumval) + "<br>\n");
            tempsb.append("Thank you for trying this form.<br>\n");
            html_response.insert(idx, tempsb.toString());
        }

        return html_response.toString();
    }

}


// These are two helpder classes. RequestHTTPHEader is to process the client side request
// and ResponseHTTPHeader is to process the server reply. In both cases this is done by
// making default values based on common HTTP headers.
class RequestHTTPHeader {
    String method;
    String target;
    String target_params;
    String version;
    String host;
    String port;
    String user_agent;
    String accept;
    String accept_language;
    String accept_encoding;

    RequestHTTPHeader(StringBuffer sb) throws InvalidObjectException{
        this(sb.toString());
    }

    RequestHTTPHeader(String s) throws InvalidObjectException {
        String[] headerlines = s.split("(?<=\\n)");

        // Per RFC7230 :  request-line   = method SP request-target SP HTTP-version CRLF
        String[] requestlines = headerlines[0].split(" ");
        if (requestlines.length != 3){
            throw new InvalidObjectException("HTTP request line invalid");
        }
        this.method = requestlines[0];
        this.version = requestlines[2];
        parseTarget(requestlines[1]);
        this.target = "." + this.target;
    }

    private void parseTarget(String tgt){
        String[] temps = tgt.split("\\?");
        if(temps.length == 1){
            this.target = temps[0];
        } else if(temps.length == 2){
            this.target = temps[0];
            this.target_params = temps[1];
        } else {
            this.target = tgt;
        }
    }

}

class ResponseHTTPHeader {
    String status;
    String reason;
    String version;
    String date;
    String server_type;
    String content_type;
    String content_length;
    String connection;
    String allow;

    ResponseHTTPHeader(int code, int length) throws InvalidObjectException{
        // I can currently respond in 3 ways: 200, 404 and 405
        switch (code){
            case 200:
                this.status = "200";
                this.reason = "OK";
                break;
            case 404:
                this.status = "404";
                this.reason = "Not Found";
                break;
            case 405:
                this.status = "405";
                this.reason = "Method Not Allowed";
                break;
            default:
                throw new InvalidObjectException("Invalid status code");
        }

        this.version = "HTTP/1.1";
        this.date = new Date().toString();
        this.content_type = "text/html; charset=ISO-8859-4";
        this.content_length = String.valueOf(length)+10;
        this.server_type = "Panda 1.0";


    }

    // method to get the full rebuilt server side response header.
    String getHeader(){
        // Per RFC: status-line = HTTP-version SP status-code SP reason-phrase CRLF
        StringBuffer tempheader = new StringBuffer();
        String crlf = "\r\n";
        tempheader.append(this.version + " " + this.status + " " + this.reason + crlf);
        tempheader.append("Date: " + this.date + crlf);
        tempheader.append("Server: " + this.server_type + crlf);
        tempheader.append("Last-Modified: " + date + crlf);
        tempheader.append("Content-Type: " + this.content_type + crlf);
        tempheader.append("Content-Length: " + this.content_length + crlf);
        if(this.status.equals("405")){
            tempheader.append("Allow: GET" + crlf);
        }
        tempheader.append("Vary: Accept-Encoding" + crlf);
        tempheader.append("Connection: close"+ crlf);

        tempheader.append(crlf);

        return tempheader.toString();
    }
}
