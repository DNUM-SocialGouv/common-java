package fr.gouv.dnum.proconnect.tomcat;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@Slf4j
@SpringBootApplication
@ComponentScan(basePackages = {"fr.gouv.dnum"})
public class ProConnectApplication {

    public static void main(String[] args) {
        SpringApplication.run(ProConnectApplication.class, args);
    }

}