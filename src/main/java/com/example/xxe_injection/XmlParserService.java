package com.example.xxe_injection;

// CÁC IMPORT CẦN THIẾT
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.StringReader;
import javax.xml.XMLConstants; // Import quan trọng bị thiếu

@Service
public class XmlParserService {

    private DocumentBuilder createVulnerableBuilder() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

        // BẬT CÁC TÍNH NĂNG NGUY HIỂM ĐỂ CHO PHÉP OOB
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", true);
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, false);

        return dbf.newDocumentBuilder();
    }

    private DocumentBuilder createSecureBuilder() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        return dbf.newDocumentBuilder();
    }

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

    public String parseLevel5(String xml) {
        try {
            createVulnerableBuilder().parse(new InputSource(new StringReader(xml)));
            return "Data processed successfully.";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    public String parseLevel6(String xml) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", true);
            DocumentBuilder dBuilder = dbf.newDocumentBuilder();
            dBuilder.parse(new InputSource(new StringReader(xml)));
            return "Data processed.";
        } catch (Exception e) {
            return "An exception occurred: " + e.toString();
        }
    }

    public String parseSvg(String svgContent) {
        try {
            Document doc = createVulnerableBuilder().parse(new InputSource(new StringReader(svgContent)));
            return "SVG file processed. It contains " + doc.getElementsByTagName("*").getLength() + " elements.";
        } catch (Exception e) {
            return "Error processing SVG: " + e.getMessage();
        }
    }

    public String parseLevel8(String xml) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setXIncludeAware(true);
            dbf.setNamespaceAware(true);

            DocumentBuilder dBuilder = dbf.newDocumentBuilder();
            Document doc = dBuilder.parse(new InputSource(new StringReader(xml)));
            return "XInclude Parsed: " + doc.getDocumentElement().getTextContent();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // --- LEVEL 9: Truly Blind XXE (No Error Feedback) ---
    public String parseLevel9(String xml) {
        try {
            createVulnerableBuilder().parse(new InputSource(new StringReader(xml)));
            return "Request processed.";
        } catch (Exception e) {
            return "Request processed.";
        }
    }
}