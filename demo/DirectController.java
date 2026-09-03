import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;

class DirectController {
    private static final Logger log = LoggerFactory.getLogger(DirectController.class);

    @GetMapping("/direct")
    void handle(String userInput) {
        log.info(userInput);
    }
}