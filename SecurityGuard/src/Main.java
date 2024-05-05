import javax.swing.JOptionPane;

public class Main {

    public static void main(String[] args) {
        // Prompt the user for the IP address to be scanned
        String ipAddress = JOptionPane.showInputDialog(null, "Enter the IP address to be scanned:",
                "IP Address scanning", JOptionPane.QUESTION_MESSAGE);
        if (ipAddress != null && !ipAddress.isEmpty()) {
            // Call the method to verify the security of the IP address
            VirusTotalChecker.verifyIP(ipAddress);
        } else {
            JOptionPane.showMessageDialog(null, "You must enter a valid IP address", "Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }
}

