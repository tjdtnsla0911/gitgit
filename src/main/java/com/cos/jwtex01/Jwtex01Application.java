package com.cos.jwtex01;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Jwtex01Application {

	public static void main(String[] args) {
		System.out.println("시작");
		SpringApplication.run(Jwtex01Application.class, args);
		System.out.println("끝");
	}

}
