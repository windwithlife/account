package com.simple.account.security;

import com.alibaba.fastjson.JSON;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.simple.account.controller.AccountController;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.springframework.web.bind.annotation.GetMapping;


import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

public class JwtUtils {
    static RsaJsonWebKey jwk = null;
    static  String keyId = "define_test";



    private static String decodeBase64(String src) {
        return new String(Base64.getDecoder().decode(src));
    }

    private static byte[] decodeBase64ToBytes(String src) {
        return Base64.getDecoder().decode(src);
    }

    private static String encodeBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    //@GetMapping(path = "/createJWK")
    public static String generateJWK() throws Exception {
        //String keyId = "define_test";
        RsaJsonWebKey jwk = JwtUtils.generateJWKCreator();
        jwk.setKeyId(JwtUtils.keyId);
        jwk.setAlgorithm(AlgorithmIdentifiers.RSA_USING_SHA256);
        String publicKey = jwk.toJson(RsaJsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        System.out.println("publicKey: " + publicKey);
        return publicKey;

    }

    public static RsaJsonWebKey generateJWKCreator() throws Exception {
        String keyId = JwtUtils.keyId;

        if (null == JwtUtils.jwk) {
            JwtUtils.jwk = JwtUtils.refreshJWKCreator(JwtUtils.keyId);
            //JwtUtils.jwk = RsaJwkGenerator.generateJwk(2048);
            //JwtUtils.jwk.setKeyId(JwtUtils.keyId);
            //JwtUtils.jwk.setAlgorithm(AlgorithmIdentifiers.RSA_USING_SHA256);
            //return JwtUtils.jwk;
        }

        //RsaJsonWebKey jwk = JwtUtils.jwk;
        //PublicKey key = jwk.getPublicKey();
        //RSAPublicKey keyRSA = jwk.getRsaPublicKey();
        //jwk.setKeyId(keyId);
        //jwk.setAlgorithm(AlgorithmIdentifiers.RSA_USING_SHA256);
        //System.out.println(encodeBase64(jwk.getRsaPublicKey().getEncoded()));
        //System.out.println(encodeBase64(jwk.getRsaPrivateKey().getEncoded()));
        //String publicKey = JwtUtils.jwk.toJson(RsaJsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        //String privateKey = jwk.toJson(RsaJsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);
        //System.out.println("publicKey: " + publicKey);
        //System.out.println("privateKey: " + privateKey);

        return  JwtUtils.jwk;

    }

    public static RsaJsonWebKey refreshJWKCreator(String keyId) throws Exception {
        RsaJsonWebKey jwk  = RsaJwkGenerator.generateJwk(2048);
        jwk.setKeyId(keyId);
        jwk.setAlgorithm(AlgorithmIdentifiers.RSA_USING_SHA256);
        //String publicKey = jwk.toJson(RsaJsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        return jwk;
    }

    //@GetMapping(path = "/createToken")
    public static String createToken() throws Exception {

        JwtClaims claims = new JwtClaims();
        claims.setIssuer("auth0");  // who creates the token and signs it
        //claims.setAudience("Audience"); // to whom the token is intended to be sent
        //claims.setExpirationTimeMinutesInTheFuture(10); // time when the token will expire (10 minutes from now)
        //claims.setGeneratedJwtId(); // a unique identifier for the token
        //claims.setIssuedAtToNow();  // when the token was issued/created (now)
        //claims.setNotBeforeMinutesInThePast(2); // time before which the token is not yet valid (2 minutes ago)
        //claims.setSubject("subject"); // the subject/principal is whom the token is about
        claims.setClaim("email", "mailx@example.com"); // additional claims/attributes about the subject can be added
        //List<String> groups = Arrays.asList("group-one", "other-group", "group-three");
        //claims.setStringListClaim("groups", groups); // multi-valued claims work too and will end up as a JSON array

        JsonWebSignature jws = new JsonWebSignature();

        // The payload of the JWS is JSON content of the JWT Claims
        jws.setPayload(claims.toJson());

        // The JWT is signed using the private key
        RsaJsonWebKey rsaJsonWebKey = JwtUtils.generateJWKCreator();
        jws.setKey(rsaJsonWebKey.getRsaPrivateKey());
        jws.setKeyIdHeaderValue(rsaJsonWebKey.getKeyId());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        String jwt = jws.getCompactSerialization();
        System.out.println("JWT: " + jwt);


        return jwt;

    }

    //@GetMapping(path = "/vtoken")
    public static String verifyTokenValues(String token) {
        try {

            if ((null == token) || (token.length() <= 0)) {
                token = createToken();
            }
            RsaJsonWebKey rsaJsonWebKey = JwtUtils.generateJWKCreator();
            RSAPublicKey publicKey = rsaJsonWebKey.getRsaPublicKey();
            RSAPrivateKey privateKey = rsaJsonWebKey.getRsaPrivateKey();
            Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer("auth0")
                    .build(); //Reusable verifier instance
            DecodedJWT jwtor = verifier.verify(token);
            String algorithmName = jwtor.getAlgorithm();
            String keyId = jwtor.getKeyId();
            Map<String, Claim> token_claims = jwtor.getClaims();
            Claim claim = token_claims.get("email");
            System.out.println("Email: " + claim.asString());
        } catch (Exception e) {
            System.out.println("failed to decode");
            e.printStackTrace();
        }
        return token;
    }

    public static String createToken2() throws Exception {
        RsaJsonWebKey rsaJsonWebKey = JwtUtils.generateJWKCreator();
        RSAPublicKey publicKey = rsaJsonWebKey.getRsaPublicKey();
        RSAPrivateKey privateKey = rsaJsonWebKey.getRsaPrivateKey();
        try {
            Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);
            String token = JWT.create()
                    .withIssuer("auth0")
                    .withClaim("email", "mail@example.com")
                    .sign(algorithm);
            return token;
        } catch (JWTCreationException exception) {
            //Invalid Signing configuration / Couldn't convert Claims.
            return "none-token";
        }
    }

    public static VerificationKeys tokenKeys() {
        VerificationKeys keys = new VerificationKeys();
        try {
            String pubKeyJson = JwtUtils.generateJWK();
            List<VerificationKey> keyList = new ArrayList<VerificationKey>();
            VerificationKey key = JSON.parseObject(pubKeyJson, VerificationKey.class);
            keyList.add(key);
            keys.setKeys(keyList);
            return keys;
        } catch (Exception e) {
            return keys;
        }
    }


}


//
//
//import io.jsonwebtoken.Claims;
//import io.jsonwebtoken.Jws;
//import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.SignatureAlgorithm;
//import org.joda.time.DateTime;
//
//import java.security.PrivateKey;
//import java.security.PublicKey;
//import java.util.Base64;
//import java.util.UUID;
//
//public class JwtUtils {
//
//    private static final  String JWT_PAYLOAD_USER_KEY = "user";
//
//    /**
//     * 私钥加密 token
//     * @param userInfo 载荷中的信息
//     * @param privateKey 私钥
//     * @param expire 过期时间， 分钟
//     * @return
//     */
//    public static String generateTokenExpireInMinutes(Object userInfo, PrivateKey privateKey, int expire){
//
//        System.out.println(privateKey);
//        if(userInfo == null){
//            return null;
//        }
//        String token = Jwts.builder()
//                .claim(JWT_PAYLOAD_USER_KEY, JsonUtils.toString(userInfo))
//                .setId(createJTI())
//                .setExpiration(DateTime.now().plusMinutes(expire).toDate())
//                .signWith(privateKey, SignatureAlgorithm.RS256)
//                .compact();
//
//        return token;
//    }
//
//    /**
//     * 私钥加密 token
//     * @param userInfo 载荷中的信息
//     * @param privateKey 私钥
//     * @param expire 过期时间，秒
//     * @return
//     */
//    public static String generateTokenExpireInSeconds(Object userInfo, PrivateKey privateKey, int expire){
//
//        if(userInfo == null){
//            return null;
//        }
//        String token = Jwts.builder()
//                .claim(JWT_PAYLOAD_USER_KEY, JsonUtils.toString(userInfo))
//                .setId(createJTI())
//                .setExpiration(DateTime.now().plusSeconds(expire).toDate())
//                .signWith(privateKey, SignatureAlgorithm.RS256)
//                .compact();
//
//        return token;
//    }
//
//    private static String createJTI(){
//        return new String(Base64.getEncoder().encode(UUID.randomUUID().toString().getBytes()));
//    }
//
//
//    /**
//     * 公钥解析 token
//     * @param token
//     * @param publicKey
//     * @return
//     */
//    public static Jws<Claims> parserToken(String token, PublicKey publicKey){
//
//        return Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token);
//
//    }
//
//    /**
//     * 获取 token 中的载荷信息
//     * @param token
//     * @param publicKey
//     * @param userType
//     * @param <T>
//     * @return
//     */
//    public static <T> Payload<T> getInfoFromToken(String token, PublicKey publicKey, Class<T> userType) {
//        Jws<Claims> claimsJws = parserToken(token, publicKey);
//        Claims body = claimsJws.getBody();
//        Payload<T> claims = new Payload<>();
//        claims.setId(body.getId());
//        claims.setUserInfo(JsonUtils.toBean(body.get(JWT_PAYLOAD_USER_KEY).toString(), userType));
//        claims.setExpiration(body.getExpiration());
//        return claims;
//    }
//
//    public static <T> Payload<T> getInfoFromToken(String token, PublicKey publicKey) {
//        Jws<Claims> claimsJws = parserToken(token, publicKey);
//        Claims body = claimsJws.getBody();
//        Payload<T> claims = new Payload<>();
//        claims.setId(body.getId());
//        claims.setExpiration(body.getExpiration());
//        return claims;
//    }
//
//
//}
