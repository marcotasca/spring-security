package com.bsf.security.sec.config;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
@Slf4j
public class JwtService {

    /**
     * Chiave privata esadecimale.
     * Il minimo accettato è 256-bit.
     * @see <a href="https://www.allkeysgenerator.com/">Generatore di chiave</a>
     */
    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    /**
     * Il tempo di scadenza del token.
     */
    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;

    /**
     * Il tempo di scadenza per il token di refresh.
     */
    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;

    /**
     * Estrae lo username dal token inviato nel header della richiesta.
     *
     * @param token è la stringa di autorizzazione nel header.
     * @return la stringa contenente lo username.
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Estrae un claim dalla lista completa dei claims.
     *
     * @param token è la stringa di autorizzazione nel header.
     * @param claimsResolver la funzione che recupererà il singolo claim dalla lista.
     * @return il valore del claim richiesto.
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Genera il token solo con i dettagli dell'utente.
     *
     * @param userDetails i dettagli dell'utente.
     * @return la stringa contenente il token.
     */
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * Genera il token solo con i claims extra.
     *
     * @param extraClaims i claims aggiuntivi non fondamentali.
     * @param userDetails i dettagli dell'utente.
     * @return la stringa contenente il token.
     */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    /**
     * Genera il token di refresh solo con i dettagli dell'utente.
     *
     * @param userDetails i dettagli dell'utente.
     * @return la stringa contenente il token.
     */
    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }

    /**
     * Crea un token impostando tutti i claims necessari, i claims extra e la scadenza firmando il
     * contenuto con una chiave privata che servirà a garantirne l'autenticità dei dati.
     *
     * @param extraClaims i claims aggiuntivi non fondamentali.
     * @param userDetails i dettagli dell'utente.
     * @param expiration il tempo espresso in millisecondi per cui scadrà il token.
     * @return la stringa contenente il token.
     */
    public String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        return Jwts
                .builder()
                .setHeaderParam("typ", "JWT")
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Controlla che il token sia valido controllando che il nome presente nel token sia uguale
     * a quello presentato in ingresso e che il token non sia scaduto.
     *
     * @param token è la stringa di autorizzazione nel header.
     * @param userDetails i dettagli dell'utente.
     * @return un boolean che rappresenta la validità del token.
     */
    public boolean isValidToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    /**
     * Controlla se il token è scaduto recuperando la data di scadenza e confrontandola con la
     * data corrente.
     *
     * @param token è la stringa di autorizzazione nel header.
     * @return un boolean che rappresenta se è scaduto un token.
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Recupera la data di scadenza dal token.
     *
     * @param token è la stringa di autorizzazione nel header.
     * @return la data di scadenza del token.
     */
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Recupera tutti i claims (chiave:valore) del token JWT. Imposta la chiave privata con
     * cui sono stati firmati i claims e ne recupera il contenuto.
     *
     * @param token è la stringa di autorizzazione nel header.
     * @return claims del token.
     */
    private Claims extractAllClaims(String token) {
        try {
            return Jwts
                    .parserBuilder()
                    .setSigningKey(getSignInKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException ex) {
            log.error("JWT expired -> {}", ex.getClaims().getSubject());
        } catch (IllegalArgumentException ex) {
            log.error("Token is null, empty or only whitespace -> {}", ex.getMessage());
        } catch (MalformedJwtException ex) {
            log.error("JWT is invalid -> {}", ex.getMessage());
        } catch (UnsupportedJwtException ex) {
            log.error("JWT is not supported -> {}", ex.getMessage());
        } catch (SignatureException ex) {
            log.error("Signature validation failed -> {}", ex.getMessage());
        }

        // TODO: Questo genera NullPointerException, gestisci le eccezioni.
        return null;
    }

    /**
     * Decodifica in BASE64 la chiave segreta precedentemente creata e la modifica creando una nuova
     * chiave privata con l'algoritmo HMAC-SHA partendo dalla chiave decodificata precedentemente.
     *
     * @return chiave privata con algoritmo HMAC-SHA.
     */
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
