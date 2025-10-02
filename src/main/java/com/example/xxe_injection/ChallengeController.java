package com.example.xxe_injection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@RequestMapping("/api")
public class ChallengeController {

    @Autowired
    private XmlParserService xmlParserService;

    // ... (giữ nguyên các level 1-8)
    @PostMapping("/level1") public String handleLevel1(@RequestBody String p) { return xmlParserService.parseLevel1(p); }
    @PostMapping("/level2") public String handleLevel2(@RequestBody String p) { return xmlParserService.parseLevel2(p); }
    @PostMapping("/level3") public String handleLevel3(@RequestBody String p) { return xmlParserService.parseLevel3(p); }
    @PostMapping("/level4") public String handleLevel4(@RequestBody String p) { return xmlParserService.parseLevel4(p); }
    @PostMapping("/level5") public String handleLevel5(@RequestBody String p) { return xmlParserService.parseLevel5(p); }
    @PostMapping("/level6") public String handleLevel6(@RequestBody String p) { return xmlParserService.parseLevel6(p); }

    @PostMapping("/level7/upload-svg")
    public ResponseEntity<String> handleLevel7(@RequestParam("file") MultipartFile file) {
        if (!file.getContentType().equals("image/svg+xml")) {
            return new ResponseEntity<>("Please upload an SVG file.", HttpStatus.BAD_REQUEST);
        }
        try {
            String content = new String(file.getBytes());
            String result = xmlParserService.parseSvg(content);
            return new ResponseEntity<>(result, HttpStatus.OK);
        } catch (IOException e) {
            return new ResponseEntity<>("Failed to read file.", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/level8") public String handleLevel8(@RequestBody String p) { return xmlParserService.parseLevel8(p); }

    // THÊM ENDPOINT MỚI
    @PostMapping("/level9") public String handleLevel9(@RequestBody String p) { return xmlParserService.parseLevel9(p); }
}