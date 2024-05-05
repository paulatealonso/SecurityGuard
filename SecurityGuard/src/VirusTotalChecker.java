import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import javax.swing.JOptionPane;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class VirusTotalChecker {

    private static final String API_KEY = "8e9d9868ad57ad4a7ca5a9785e320a0310a9b3f548979999ee5fdafcfd584f5f";

    public static void verifyIP(String ipAddress) {
        try {
            URL url = new URL("https://www.virustotal.com/api/v3/ip_addresses/" + ipAddress);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            con.setRequestProperty("x-apikey", API_KEY);

            int responseCode = con.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
                String inputLine;
                StringBuilder response = new StringBuilder();
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                in.close();

                JsonObject jsonObject = JsonParser.parseString(response.toString()).getAsJsonObject();

                // Build the relevant information to be displayed
                StringBuilder infoBuilder = new StringBuilder();
                infoBuilder.append("IP Address: ").append(ipAddress).append("\n");

                // Obtain and aggregate relevant information
                JsonElement countryElement = jsonObject.get("country");
                if (countryElement != null && !countryElement.isJsonNull()) {
                    infoBuilder.append("Country: ").append(countryElement.getAsString()).append("\n");
                }
                
                JsonElement continentElement = jsonObject.get("continent");
                if (continentElement != null && !continentElement.isJsonNull()) {
                    infoBuilder.append("Continent: ").append(continentElement.getAsString()).append("\n");
                }
                
                JsonElement ispElement = jsonObject.get("as_owner");
                if (ispElement != null && !ispElement.isJsonNull()) {
                    infoBuilder.append("ISP: ").append(ispElement.getAsString()).append("\n");
                }
                
                JsonElement reputationElement = jsonObject.get("reputation");
                if (reputationElement != null && !reputationElement.isJsonNull()) {
                    infoBuilder.append("Reputation: ").append(reputationElement.getAsInt()).append("\n");
                }
                
                JsonObject lastAnalysisStats = jsonObject.getAsJsonObject("last_analysis_stats");
                if (lastAnalysisStats != null) {
                    int maliciousCount = lastAnalysisStats.getAsJsonPrimitive("malicious").getAsInt();
                    infoBuilder.append("Malicious: ").append(maliciousCount > 0 ? "Yes" : "No").append("\n");
                }

                // Display information in a dialog box
                JOptionPane.showMessageDialog(null, infoBuilder.toString(), "IP Information",
                        JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(null, "Failed to verify IP address. Response code: " + responseCode,
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        } catch (IOException e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(null, "Error occurred: " + e.getMessage(), "Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    public static void main(String[] args) {
        String ipAddress = JOptionPane.showInputDialog("Enter the IP Address:");
        if (ipAddress != null && !ipAddress.isEmpty()) {
            verifyIP(ipAddress);
        } else {
            JOptionPane.showMessageDialog(null, "No IP Address provided.", "Error", JOptionPane.ERROR_MESSAGE);
        }
    }
}










