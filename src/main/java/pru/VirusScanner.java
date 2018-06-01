package pru;

import pru.clamav.*;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import java.io.IOException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;
@RestController
public class VirusScanner {

    @Value("${clamav.host}")
    private String hostname;

    //@Value("${clamav.port}")
    //private int port;

    @Value("${clamav.timeout}")
    private int timeout;

    /**
     * @return Clamd status.
     */
    @RequestMapping("/")
    public String ping() throws IOException {
      ClamAVClient a = new ClamAVClient(hostname, 3310, timeout);
      return "ClamAV Status: " + a.ping() + "<br>"+"ClamAV Host: " + hostname + "<br>"+"ClamAV Port: 3310";
    }

    /**
     * @return Clamd scan result
     */
    @RequestMapping(value="/scan", method=RequestMethod.POST)
    public @ResponseBody String handleFileUpload(@RequestParam("fileToUpload") MultipartFile file) throws IOException{
    	System.out.println("Here I am in Scan Method");
    	System.out.println("Host Name:"+hostname);
    	System.out.println("Port: 3310");

    	if (!file.isEmpty()) {
        ClamAVClient a = new ClamAVClient(hostname, 3310, timeout);
        byte[] r = a.scan(file.getInputStream());
        String s = new String(r);
        return "Everything ok : " + ClamAVClient.isCleanReply(r) + "<br><br>"+s+"<br><br> <a href='fileupload.html'>File Upload</a>";
      } else throw new IllegalArgumentException("empty file");
    }
}