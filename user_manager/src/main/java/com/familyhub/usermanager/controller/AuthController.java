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

/**
 * 認証関連のエンドポイントを提供するコントローラー
 * <p>
 * ユーザーの登録、ログイン、及び認証済みユーザーの情報取得のためのRESTエンドポイントを提供する。
 * </p>
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    /**
     * AuthControllerのコンストラクタ
     *
     * @param authService ユーザー認証および登録処理を提供するAuthService
     */
    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * ユーザー登録エンドポイント
     * <p>
     * リクエストボディに含まれる"username"、"password"、および"email"の値を用いて新規ユーザーを登録する。
     * 登録成功：登録されたユーザー名を含むメッセージを返す。
     * 登録失敗：400(BAD REQUEST)を返す。
     * </p>
     *
     * @param req ユーザー登録情報を含むリクエストボディ（"username"、"password"、"email"がキー）
     * @return 登録結果のメッセージまたはエラーメッセージ
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> req) {
        try {
            User user = authService.register(
                    req.get("username"),
                    req.get("password"),
                    req.get("email")
            );
            return ResponseEntity.ok("User registered: " + user.getUsername());
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

    /**
     * ログインエンドポイント
     * <p>
     * リクエストボディに含まれる"username"と"password"を用いて認証を行い、
     * 認証に成功した場合はJWTトークンを返します。認証に失敗した場合は401(UNAUTHORIZED)を返します。
     * </p>
     *
     * @param req ログイン情報を含むリクエストボディ（"username"、"password"がキー）
     * @return JWTトークンを含むレスポンスまたはエラーメッセージ
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> req) {
        try {
            String token = authService.login(req.get("username"), req.get("password"));
            Map<String, String> res = new HashMap<>();
            res.put("accessToken", token);
            return ResponseEntity.ok(res);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }
    
    /**
     * 認証済みユーザ情報取得エンドポイント。
     * <p>
     * Spring Security によってリクエスト時に提供される
     * {@link org.springframework.security.core.Authentication} オブジェクトを用いて、
     * ユーザーが認証済みかどうかを判断する。
     * 認証済み：ユーザー名および権限情報をレスポンスとして返す。
     * 未認証  ：401 (UNAUTHORIZED) を返す。
     * </p>
     *
     * @param authentication リクエスト時に Spring Security によって注入される認証情報。
     *                       認証済みの場合は非null、それ以外はnullとなる。
     * @return 認証済みの場合はユーザー名と権限情報を含むレスポンス、認証されていない場合はエラーメッセージ
     */
    @GetMapping("/userinfo")
    public ResponseEntity<?> userInfo(Authentication authentication) {
        if (authentication == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                 .body("User not authenticated");
        }
        Map<String, Object> info = new HashMap<>();
        info.put("username", authentication.getName());
        info.put("authorities", authentication.getAuthorities());
        return ResponseEntity.ok(info);
    }
}
