package com.example.xxe_injection;

import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.StringReader;

@Service
public class XmlParserService {

    // Helper method to create a vulnerable parser
    private DocumentBuilder createVulnerableBuilder() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // Allow everything for maximum vulnerability
        return dbf.newDocumentBuilder();
    }

    // Helper method to create a Ssecure parser
    private DocumentBuilder createSecureBuilder() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        return dbf.newDocumentBuilder();
    }

    // --- LEVEL 1-4 (Giữ nguyên logic cũ nhưng dùng helper) ---
    public String parseLevel1(String xml) {
        try {
            Document doc = createVulnerableBuilder().parse(new InputSource(new StringReader(xml)));
            return "Parsed XML content: " + doc.getDocumentElement().getTextContent();
        } catch (Exception e) { return "Error: " + e.getMessage(); }
    }
    public String parseLevel2(String xml) {
        if (xml.toLowerCase().contains("system") || xml.toLowerCase().contains("file://")) {
            return "Malicious input detected by filter!";
        }
        return parseLevel1(xml);
    }
    public String parseLevel3(String xml) {
        if (xml.toLowerCase().contains("<!doctype")) {
            return "Malicious DTD detected by filter!";
        }
        return parseLevel1(xml);
    }
    public String parseLevel4(String xml) {
        try {
            Document doc = createSecureBuilder().parse(new InputSource(new StringReader(xml)));
            return "Parsed XML content (securely): " + doc.getDocumentElement().getTextContent();
        } catch (Exception e) { return "Error: " + e.getMessage(); }
    }

    // --- LEVEL 5: Blind XXE (Out-of-Band) ---
    public String parseLevel5(String xml) {
        try {
            // Vulnerable parser, but the response doesn't show the content
            createVulnerableBuilder().parse(new InputSource(new StringReader(xml)));
            return "Data processed successfully."; // No content is returned
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // --- LEVEL 6: Error-based Blind XXE ---
    public String parseLevel6(String xml) {
        // This level has a specific configuration that reveals errors
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // It allows external DTDs but might have issues resolving them, leading to errors
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", true);
            DocumentBuilder dBuilder = dbf.newDocumentBuilder();
            dBuilder.parse(new InputSource(new StringReader(xml)));
            return "Data processed.";
        } catch (Exception e) {
            // The error message itself is the vulnerability
            return "An exception occurred: " + e.toString();
        }
    }

    // --- LEVEL 7: XXE via File Upload (SVG) ---
    // Controller sẽ xử lý file upload, service chỉ cần phân tích
    public String parseSvg(String svgContent) {
        try {
            Document doc = createVulnerableBuilder().parse(new InputSource(new StringReader(svgContent)));
            // Simulate rendering the SVG, which might trigger the XXE
            return "SVG file processed. It contains " + doc.getElementsByTagName("*").getLength() + " elements.";
        } catch (Exception e) {
            return "Error processing SVG: " + e.getMessage();
        }
    }

    // --- LEVEL 8: XInclude Attack ---
    public String parseLevel8(String xml) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // DTDs are disabled, but XInclude is enabled!
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setXIncludeAware(true); // The vulnerability!
            dbf.setNamespaceAware(true); // Required for XInclude

            DocumentBuilder dBuilder = dbf.newDocumentBuilder();
            Document doc = dBuilder.parse(new InputSource(new StringReader(xml)));
            return "XInclude Parsed: " + doc.getDocumentElement().getTextContent();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}