import java.net.*;

/*
 * This is a simple program to test SSL connections from a Java client.
 */
public class TestHTTPConnection {

    public static void main(String[] args) throws Exception {
        int argIndex;
        for (argIndex = 0; argIndex < args.length; ++argIndex) {
            String arg = args[argIndex];

            if (!arg.startsWith("-"))
                break;
            else if ("--".equals(arg))
                break;
            else if ("--help".equals(arg) || "-h".equals(arg) || "-help".equals(arg)) {
                usage();
                System.exit(0);
            } else {
                System.err.println("Unrecognized option: " + arg);
                System.exit(1);
            }
        }

        URL url = null;
        if (argIndex == args.length - 1) {
            url = new URL(args[argIndex++]);
        } else if (argIndex < args.length) {
            System.err.println("Unexpected additional arguments: "
                + java.util.Arrays.asList(args).subList(argIndex + 1, args.length));
            usage();
            System.exit(1);
        } else {
            System.err.println("Expected url");
            usage();
            System.exit(1);
        }

        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.getInputStream().read();
        System.out.println("Successfully connected to " + url);
    }

    private static void usage() {
        String command = TestHTTPConnection.class.getName();

        System.out.println("Usage: java " + command + " [opts] url");
    }
}
