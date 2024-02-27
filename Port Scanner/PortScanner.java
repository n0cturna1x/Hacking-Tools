/* Port Scanner */

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PortScanner {
    // Logger
    private static final Logger LOGGER = Logger.getLogger(PortScanner.class.getName());
    // Specific ports to scan
    private static final int[] ports = {80, 443, 22, 25, 53};
    // Regex pattern for checking IP address
    private static final String IPV4_PATTERN = "^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\\.(?!$)|$)){4}$";
    // Default timeout to 100ms
    private final static int TIMEOUT = 100;

    public static void main(String[] args) {

    // Checks and validates arguments
    String host = null;
    if (args.length > 0 && isValidIpString(args[0])) {
        host = args[0];
    } else {
        System.err.println("Invalid IP. Try again.");
        System.exit(0);
    }
    for (int p : ports) {
        if (checkPort(host, p)) {
            System.out.println("Host: " + host + " port: " + p + " is open");
        }
    }
    }
    
    // Returns true if the string matches IPv4 or 'localhost', otherwise returns false
    private static boolean isValidIpString(String ip) {
        if ("localhost".equals(ip)) {
            return true;
        }
        Pattern pattern = Pattern.compile(IPV4_PATTERN);
        Matcher matcher = pattern.matcher(ip);
        return matcher.matches();
    }
    
    // Returns true if the connection is successful, otherwise returns false
    private static boolean checkPort(String host, int port) {
        Socket socket = null;
        try {
            socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), TIMEOUT);
            socket.setSoTimeout(TIMEOUT);
            return true;
        } catch (Exception e) {
            return false;
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException e) {
                    LOGGER.log(Level.SEVERE, "Exception occured", e);
                }
            }
        }
    }
}