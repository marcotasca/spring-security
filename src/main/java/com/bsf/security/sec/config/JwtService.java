package com.bsf.security.sec.config;

import com.bsf.security.exception._common.BTExceptionResolver;
import com.bsf.security.exception.security.jwt.SecurityJWTException;
import com.bsf.security.sec.model.token.JWTStateEnum;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Slf4j
@Service
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

    @Autowired
    private BTExceptionResolver btExceptionResolver;

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
        return claims == null ? null : claimsResolver.apply(claims);
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
        extraClaims.put("roles", userDetails.getAuthorities());

        return Jwts
                .builder()
                .setHeaderParam("typ", "JWT")
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .setIssuer("Biotekna")
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
            Object[] args = new Object[] {ex.getClaims()};
            btExceptionResolver.resolveAuthBTException(
                    JWTStateEnum.JWT_EXPIRED.name(), new SecurityJWTException(ex.getMessage(), args), token
            );
        } catch (IllegalArgumentException ex) {
            btExceptionResolver.resolveAuthBTException(
                    JWTStateEnum.TOKEN_NULL_EMPTY_OR_WHITESPACE.name(), new SecurityJWTException(ex.getMessage()), token
            );
        } catch (MalformedJwtException ex) {
            btExceptionResolver.resolveAuthBTException(
                    JWTStateEnum.JWT_INVALID.name(), new SecurityJWTException(ex.getMessage()), token
            );
        } catch (UnsupportedJwtException ex) {
            btExceptionResolver.resolveAuthBTException(
                    JWTStateEnum.JWT_NOT_SUPPORTED.name(), new SecurityJWTException(ex.getMessage()), token
            );
        } catch (SignatureException ex) {
            btExceptionResolver.resolveAuthBTException(
                    JWTStateEnum.SIGNATURE_VALIDATION_FAILED.name(), new SecurityJWTException(ex.getMessage()), token
            );
        }

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
