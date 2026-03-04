import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;

/**
 * Java implementation of the custom GatewayScript signature policy.
 * This class handles reading context data, constructing the signing payload,
 * loading the private key (from PEM), and performing the RSA-SHA256 signing.
 *
 * REQUIRES: Jackson databind dependency for JSON processing.
 */
public class SignatureGenerator {

    /**
     * Generates an RSA-SHA256 signature based on the request data and a private key.
     *
     * @param clientSecret The x-ibm-client-secret header value.
     * @param pathValue The resolved path value (e.g., /api/v1/resource).
     * @param queryString The raw query string (e.g., param1=value1&param2=value2).
     * @param method The HTTP method (e.g., "POST", "GET").
     * @param requestBody The raw request body as a string.
     * @param privateKeyPem The private key content in PKCS#8 PEM format.
     * @return The Base64 encoded signature string.
     * @throws Exception if an error occurs during JSON parsing, key loading, or signing.
     */
    public String generateSignature(
        String clientSecret,
        String pathValue,
        String queryString,
        String method,
        String requestBody,
        String privateKeyPem) throws Exception {

        System.out.println("LENIN LOG TESTING");
        System.out.println("client secret : " + clientSecret);

        // 1. Determine the timestamp and standardized body (as done in the GatewayScript)
        String timeStamp = "";
        String body = "";

        // Jackson ObjectMapper for JSON processing
        ObjectMapper objectMapper = new ObjectMapper();

        if (!"GET".equalsIgnoreCase(method) && requestBody != null && !requestBody.isEmpty()) {
            try {
                // Read body as JSON
                JsonNode rootNode = objectMapper.readTree(requestBody);

                // Extract timestamp: JSON.parse(json.toString('utf8')).header.transctionDateTime
                JsonNode headerNode = rootNode.path("header");
                if (headerNode.has("transctionDateTime")) {
                    timeStamp = headerNode.get("transctionDateTime").asText();
                }

                // Standardized body: The script implies re-stringifying the parsed JSON
                body = objectMapper.writeValueAsString(rootNode);

            } catch (Exception e) {
                // Handle cases where body is not valid JSON or structure is unexpected
                System.err.println("Error parsing request body: " + e.getMessage());
                // The original script would throw an error here if JSON.parse failed.
                throw new IllegalArgumentException("Invalid JSON body or missing transactionDateTime in header.", e);
            }
        }

        // Handle null/empty query string as empty string
        String finalQueryString = (queryString != null && !queryString.isEmpty()) ? queryString : "";

        // 2. Construct the dataToSign string
        // dataToSign = securityKey +","+timeStamp+","+pathvalue +","+querystring +"," +body;
       String dataToSign = String.join(",", clientSecret, timeStamp, pathValue, finalQueryString, body);
	//	String dataToSign="fileType:PAYLOAD~fileContent:ALBI 13021680 SA4915000764130216800007 SAR 20240911 1250 20240911 20240610131600 91-9042865640 201812 100 SA0515000921107971490009 Mohammed Yahya BIN ALBI SALARY 100 0 0 0 2783102375 200 SA8730300001008080654500 محمد عمار عامر المطيري ARNB SALARY 200 0 0 0 1000000026 300 SA4915000901100018150011 SHORT NAME ALBI SALARY 300 0 0 0 1735197731 400 SA6415000555140505790016 Test company ALBI BONUS 400 0 0 0 1140505791 250 SA6715000722100018230029 SHORT NAME ALBI SALARY 250 0 0 0 1255372763~fileName:13021680.SAL.202224.17131611.txt~employeeCount:10~totalAmount:1000~executionDate:29-11-2022";

/*
		String dataToSign="fileType:PAYLOAD~fileContent:ALBI	13021680	SA4915000764130216800007	SAR	20240911	1250	20240911	20240610131600		91-9042865640	201812"+
"100	SA0515000921107971490009	Mohammed Yahya BIN	ALBI	SALARY		100	0	0	0	2783102375"+
"200	SA8730300001008080654500	محمد عمار عامر المطيري	ARNB	SALARY		200	0	0	0	1000000026"+
"300	SA4915000901100018150011	SHORT NAME	ALBI	SALARY		300	0	0	0	1735197731"+
"400	SA6415000555140505790016	Test company	ALBI	BONUS		400	0	0	0	1140505791"+
"250	SA6715000722100018230029	SHORT NAME	ALBI	SALARY		250	0	0	0	1255372763~fileName:13021680.SAL.202224.17131611.txt~employeeCount:10~totalAmount:1000~executionDate:29-11-2022";
*/
        System.out.println("dataToSign : " + dataToSign);

        // 3. Load the Private Key
        PrivateKey privateKey = loadPrivateKey(privateKeyPem);

        // 4. Perform RSA-SHA256 Signing
        // 'rsa-sha256' maps to "SHA256withRSA" in Java
        Signature rsaSha256 = Signature.getInstance("SHA256withRSA");
        rsaSha256.initSign(privateKey);
        
        // Update signature with the payload bytes (using UTF-8 encoding)
        rsaSha256.update(dataToSign.getBytes(StandardCharsets.UTF_8));
        
        byte[] signatureBytes = rsaSha256.sign();

        // 5. Base64 Encode the signature
        String base64Signature = Base64.getEncoder().encodeToString(signatureBytes);

        System.out.println("signature with rsa-sha256 is " + base64Signature);

        // This is the value that would be set in the 'x-bab-signature' header
        return base64Signature;
    }

    /**
     * Helper method to load a PrivateKey object from a PEM string (PKCS#8 format).
     * This method removes the header/footer and Base64-decodes the content.
     */
    private PrivateKey loadPrivateKey(String pemContent) throws Exception {
        // Remove PEM header, footer, and newlines
        String cleanedPem = pemContent
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(cleanedPem);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        
        // Assuming RSA key algorithm, matching the SHA256withRSA signature
        KeyFactory kf = KeyFactory.getInstance("RSA"); 
        return kf.generatePrivate(spec);
    }

public static void main(String a[]) throws Exception{
	 String clientSecret="44e913bbae38b1fbddf65c413c1d73a0";
    	 String pathValue="/v1/real-estate/nhc/escrow-accounts";
    	 String queryString= "";
    	 String method="POST";
    	String  requestBody="{\r\n"
    	                + "  \"header\": {\r\n"
    	                + "    \"agentId\": \"13401896\",\r\n"
    	                + "    \"tppId\": \"911\",\r\n"
    	                + "    \"transctionDateTime\": \"2024-01-16T15:33:22\",\r\n"
    	                + "    \"clientReferenceNumber\": \"FT20191125120073\",\r\n"
    	                + "    \"requesterInfo1\": \"string\",\r\n"
    	                + "    \"requesterInfo2\": \"string\",\r\n"
    	                + "    \"requesterInfo3\": \"string\",\r\n"
    	                + "    \"requestMode\": \"0\",\r\n"
    	                + "    \"language\": \"E\",\r\n"
    	                + "    \"deviceInfo\": {\r\n"
    	                + "      \"model\": \"Iphone 15 Pro max\",\r\n"
    	                + "      \"osType\": \"IOS\",\r\n"
    	                + "      \"osVersion\": \"17.2.1\",\r\n"
    	                + "      \"id\": \"sdf2323-3223-sfsd-323\",\r\n"
    	                + "      \"ipAdress\": \"1xx.125.524.365\",\r\n"
    	                + "      \"city\": \"Riyadh\",\r\n"
    	                + "      \"country\": \"KSA\"\r\n"
    	                + "    }\r\n"
    	                + "  },\r\n"
    	                + "  \"data\": {\r\n"
    	                + "    \"acceptTermsNConditions\": \"\",\r\n"
    	                + "    \"projectInfo\": {\r\n"
    	                + "      \"nameEnglish\": \"GB Project Name\",\r\n"
    	                + "      \"nameArabic\": \"AR Project Name\",\r\n"
    	                + "      \"NHCprojectNumber\": \"Project Number\",\r\n"
    	                + "      \"area\": \"\",\r\n"
    	                + "      \"unitsCount\": 1\r\n"
    	                + "    },\r\n"
    	                + "    \"applicantInfo\": {\r\n"
    	                + "      \"nameEnglish\": \"Applicant's name English\",\r\n"
    	                + "      \"nameArabic\": \"Applicant's name Arabic\",\r\n"
    	                + "      \"birthDate\": \"Applicant's birth date\",\r\n"
    	                + "      \"mobileNo\": \"Applicant's mobile\",\r\n"
    	                + "      \"nationality\": \"Applicant's Nationality\",\r\n"
    	                + "      \"idNumber\": \"Applicant's Id\"\r\n"
    	                + "    },\r\n"
    	                + "    \"realEstateCompanyInfo\": {\r\n"
    	                + "      \"unifiedNumber\": \"\",\r\n"
    	                + "      \"nameArabic\": \"\",\r\n"
    	                + "      \"nameEnglish\": \"\",\r\n"
    	                + "      \"mobileNumber\": \"\",\r\n"
    	                + "      \"nationality\": \"\",\r\n"
    	                + "      \"residence\": \"\",\r\n"
    	                + "      \"address\": \"\"\r\n"
    	                + "    }\r\n"
    	                + "  },\r\n"
    	                + "  \"authorizedSignatoryInfo\": [\r\n"
    	                + "    {\r\n"
    	                + "      \"nationality\": \"\",\r\n"
    	                + "      \"idNumber\": \"\",\r\n"
    	                + "      \"dateOfBirth\": \"\",\r\n"
    	                + "      \"mobileNumber\": \"\"\r\n"
    	                + "    }\r\n"
    	                + "  ],\r\n"
    	                + "  \"taxInfo\": [\r\n"
    	                + "    {\r\n"
    	                + "      \"taxDeclartion\": \"FATCA\",\r\n"
    	                + "      \"taxNumber\": \"12345\"\r\n"
    	                + "    }\r\n"
    	                + "  ],\r\n"
    	                + "  \"legalConsultationInfo\": {\r\n"
    	                + "    \"unifiedNumber\": \"\",\r\n"
    	                + "    \"nameEnglish\": \"\",\r\n"
    	                + "    \"nameArabic\": \"string\",\r\n"
    	                + "    \"officeName\": \"\",\r\n"
    	                + "    \"idNumber\": \"\",\r\n"
    	                + "    \"mobileNumber\": \"\",\r\n"
    	                + "    \"nationality\": \"\"\r\n"
    	                + "  },\r\n"
    	                + "  \"engineerConsultationInfo\": {\r\n"
    	                + "    \"unifiedNumber\": \"\",\r\n"
    	                + "    \"nameEnglish\": \"\",\r\n"
    	                + "    \"nameArabic\": \"string\",\r\n"
    	                + "    \"officeName\": \"\",\r\n"
    	                + "    \"idNumber\": \"\",\r\n"
    	                + "    \"mobileNumber\": \"\",\r\n"
    	                + "    \"nationality\": \"\"\r\n"
    	                + "  }\r\n"
    	                + "}";
    	/* working
		String privateKeyPem="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";

		*/
		String privateKeyPem="MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQCxdGXpQnTxv1aY77NijIYY0yx+FSyW9hN34cLKCCeu+crwE0XlyDRwcR0XR3XW+PmjUt+q2SN+16RphzaFi490YxKU0hT4HnwKMBIOSYWbsQzdPl9/gn9jeSU2jZ94/oub8suLNcd6oBlzWi42OgU7VF5ZlbEeOhbP9GYvcizIunNS5mxaOx9ITJqDpEME429MXu5JrCSNONU3BfFOMANK2OG3Z65UZRHNu5vfHUiMPMcqx6MfHhtFizGUgV+ej7PJyKQyZDptQNL3rBRKoNAhnvsmTEQHcACh6uauHdAK0qjrj4u5StBEtopkuzBbKfGctp7l71xPMYzVkd8uiBL9AgMBAAECggEBAI467TP4wCLDaXVLKkxitVhQaejkr8iPkysTGD02LBhivfWOfQefX+h/wQFXlWuoQu5VDlCxmXGhBXZPmbOQGHsArXP6rjPwuxqvTMmGxD/1uInb5E8fGVtxThJbkOY5n0xvXhVGFYyDpeJ+9WshNfBHvxeukzfW91HWYdDFgn+fGoo+OJESwWrxffnbaqC5rcUkSxNIZvAasCi1XNpVx/rQTbEPQRfOPz59BGADksXlplhWzE24ZJCa7AqnAYsOJbdM6FXCsgK+5SiaDWkxkW9JTOVW4WDp+xKIDGpaDnFrXEKog/ngQHNQKresNuualoglk8I8hlzw6J3P4sS8iUECgYEAwjWypaRrVhHLiQ1cVEMVwMEw8JKixU3Y/q1UyC4Nzm/aLzLb+1UFRj+C1j0wvAHNFkCJKEkGHOSG0yHEew/KcaSHo0vlAntP/pZBVXwIZCVaVg5l9Sw68BP+fIBK9rgTGJYIE8LJRwJOgScCwYqgPUdXq//rsfVISYhXJCVtETsCgYEA6eoBn32w0RmPc1iuh3Spqd7q2fbiGX6HNyKoKofUr4LXCxfwH6nqA8sP+dBcHwOmcxa0g9wTOdT42DjJJ1/UYdsVplsE/W9646CpGRbOuGYv6+dNIKfXvsXlZuRqUPZ0A9QQNW+9h0rnJiHtOv/c5V4ziQuFJOK550tk/db4KScCgYEAnJrObvGxuBrrZJ3IeQ4LiX5/p06nQLDwrRU6S52PdosNhofdicLaWPY32+hF1yUgqrPppfmUm1HQQop1NMLb/V2uHojBp4mmTOX+0x8MaS0Rtlkv8E71S8jjqqONT3vJskaxRrYItmDuywiZGVZetmtEECdzePIQk3MEydoAJCcCgYEAvomnGMvBpBI2D7dFM4GMUpsKotHACxROAFNyuHI8hVsG4Dp3ltNJlB1svglDgN/wTf9Iu8AgyRL6QObAtBoTXkKfuAqcXfTZHWJZW96ANSTIFFktMlSGIRgCbXXSRHD8v8GWEnEa6YHSF/W60DxrK0s4n4GKyykEVavMcBkTvDECgYEAlEf6QfVx/9lcImK603wPokF9q3pW++n099CtSgd3/IBrORE82N+X+TzSyyOJGldeaXM7SSTESPzFIux9Z8ZHhb+8aK09x5rLj5vUFLlmkrYNrAqi+jwZ2865HL4suk8qhi/F2GFy/Tz+1q1NisNDo+9MMtiDf82zi3bNI1tUdno=";
    	 new SignatureGenerator().generateSignature(clientSecret,pathValue,queryString,method,requestBody,privateKeyPem);

    }
}