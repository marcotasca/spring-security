https://start.spring.io/

https://auth0.com/docs/secure/tokens/json-web-tokens

https://jwt.io/

OneToMany: LAZY<br>
ManyToOne: EAGER<br>
ManyToMany: LAZY<br>
OneToOne: EAGER<br>

OAuth Google Security Flow:

BASE_URI + /oauth2/authorize/ + [provider] ? redirect_uri= REDIRECT_URI <br>
http://localhost:8080/oauth2/authorize/google?redirect_uri=http://localhost:3000/oauth2/redirect

BASE_URI + /oauth2/callback/ + [provider] <br>
http://localhost:8080/oauth2/callback/google

Quando viene chiamata la callback viene chiamata il success handler <br>
Nella richiesta vengono applicati i cookie <br>
- request_uri


BASE_URI + /oauth2/redirect/ ? token= TOKEN <br>
http://localhost:3000/oauth2/redirect?token=TOKEN_ID

https://github.com/The-Tech-Tutor/spring-react-login