package com.familyhub.usermanager.controller;

import com.familyhub.usermanager.model.User;
import com.familyhub.usermanager.service.AuthService;
import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    // 定数の定義
    private static String USERNAME = "username";
    private static String PASSWORD = "password";

    private AuthService authService;

    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    // ユーザ登録エンドポイント
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> req) {
        try {
            User user = authService.register(
                    req.get(USERNAME),
                    req.get(PASSWORD),
                    req.get("email")
            );
            return ResponseEntity.ok("User registered: " + user.getUsername());
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

    // ログインエンドポイント
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> req) {
        try {
            String token = authService.login(req.get(USERNAME), req.get(PASSWORD));
            Map<String, String> res = new HashMap<>();
            res.put("accessToken", token);
            return ResponseEntity.ok(res);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }
    
    // 認証済みユーザ情報取得エンドポイント
    @GetMapping("/userinfo")
    public ResponseEntity<?> userInfo(Authentication authentication) {
        if (authentication == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                 .body("User not authenticated");
        }
        Map<String, Object> info = new HashMap<>();
        info.put(USERNAME, authentication.getName());
        info.put("authorities", authentication.getAuthorities());
        return ResponseEntity.ok(info);
    }
}
