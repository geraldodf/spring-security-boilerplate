# Simple Boilerplate for Spring Security

======================================

### This is a basic guide to implement Spring Security in a project.

#### 1. You need a user entity with fields like name, email, password, and role. Below are example files:

[User Entity](https://github.com/geraldodf/simplified-payment/blob/master/src/main/java/com/simplifiedpayment/data/models/User.java)

[User Role](https://github.com/geraldodf/simplified-payment/blob/master/src/main/java/com/simplifiedpayment/data/UserRole.java)

Now that your project has a user layer, you can proceed to implement Spring Security. Follow the steps below.

#### 2. Add Spring Security Dependencies

```xml
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>
```

Alternatively, you can use [Spring Initializr](https://start.spring.io/) to include Spring Security and explore the pom.xml.

Once you run your project, Spring Security will generate a default security password. You’ll see a message like this:

Then run your project, in the terminal you will see the Spring Security running and the following message:

```bash
Using generated security password: 'password'
```

You can then access /login and use the default user (user) and generated password.

#### 3. Configure the User Entity for Security

To integrate Spring Security with your user entity, implement the UserDetails interface and define the following methods:

```java
@Override
public Collection<? extends GrantedAuthority> getAuthorities() {
    if (this.userRole == UserRole.ADMIN) {
        return List.of(
            new SimpleGrantedAuthority("ROLE_ADMIN"),
            new SimpleGrantedAuthority("ROLE_USER")
        );
    } else {
        return List.of(new SimpleGrantedAuthority("ROLE_USER"));
    }
}

@Override
public String getPassword() {
    return this.password;
}

@Override
public String getUsername() {
    return this.email;
}

@Override
public boolean isAccountNonExpired() {
    return true;
}

@Override
public boolean isAccountNonLocked() {
    return true;
}

@Override
public boolean isCredentialsNonExpired() {
    return true;
}

@Override
public boolean isEnabled() {
    return true;
}
```

The getUsername() method maps to the user’s email (or any other login identifier you want). The getAuthorities() method assigns roles, such as ROLE_ADMIN and ROLE_USER, depending on the user’s role.

#### 4. Create Security Configuration

Usually, we use SecurityConfiguration inside a package called infra/security, but we can use any package.

Create a class for your security settings, typically named SecurityConfiguration, and annotate it with @Configuration and @EnableWebSecurity:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize ->
                    authorize
                        .requestMatchers(HttpMethod.POST, "/endpoint").permitAll()
                        .requestMatchers(HttpMethod.POST, "/endpoint").hasRole("ROLE")
                        .requestMatchers(HttpMethod.GET, "/endpoint").permitAll()
                        .anyRequest().authenticated()
                )
                .build();
    }
}

```
You can se an example [here](https://github.com/geraldodf/simplified-payment/blob/master/src/main/java/com/simplifiedpayment/infra/security/SecurityConfiguration.java)

Here, CSRF is disabled (often necessary for stateless APIs), sessions are stateless, and different endpoints are protected by roles.

#### 5. Implement UserDetailsService

Create a service class, such as AuthorizationService, which implements UserDetailsService to load users from your database:

```java
@Service
public class AuthorizationService implements UserDetailsService {

    private final UserService userService;

    public AuthorizationService(UserService userService) {
        this.userService = userService;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        // this method is responsible to load the user, in this case im using the Email, but you can
        // use any other identifier you want
        return this.userService.findByEmail(email);
    }
}
```

This method is responsible to load our user!

#### 6. Create Authentication Controller

Your controller will handle authentication requests. Create a class AuthenticationController with a login endpoint:

```java
@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    private final AuthenticationManager authenticationManager;

    public AuthenticationController(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthenticationDto authenticationDTO) {
        var authRequest = new UsernamePasswordAuthenticationToken(authenticationDTO.email(), authenticationDTO.password());
        var authentication = this.authenticationManager.authenticate(authRequest);

        return ResponseEntity.ok().build();
    }
}
```

#### 7. Configure AuthenticationManager

Add this bean in SecurityConfiguration to manage authentication:

```java
@Bean
public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
    return authenticationConfiguration.getAuthenticationManager();
}
```

#### 8. Add Password Encoding

You need a password encoder for hashing passwords. Add the following in SecurityConfiguration:

```java
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
```

#### 9. Register New Users

This method should be placed on the AuthenticationController.

```java
@PostMapping("/register")
public ResponseEntity<?> register(@RequestBody RegisterUserDto registerUserDto) {
    if (this.userRepository.findByEmail(registerUserDto.email()) != null) {
        return ResponseEntity.badRequest().build();
    }

    String hashedPassword = passwordEncoder().encode(registerUserDto.password());
    var user = new User(registerUserDto.name(), registerUserDto.email(), hashedPassword, registerUserDto.role());

    this.userRepository.save(user);
    return ResponseEntity.ok().build();
}
```

DTO for registration:

```java
public record RegisterUserDto(String name, String email, String password, UserRole role) {}
```

#### 10. Make Auth Endpoints Public

Allow registration and login requests to be public in your security filter chain:

```java
.requestMatchers(HttpMethod.POST, "/auth/register").permitAll()
.requestMatchers(HttpMethod.POST, "/auth/login").permitAll()
```

#### 11. Add JWT Dependencies

```xml
        <dependency>
            <groupId>com.auth0</groupId>
            <artifactId>java-jwt</artifactId>
            <version>4.4.0</version>
        </dependency>
```

#### 12. Create a TokenService for JWT

Create a TokenService class to handle JWT token creation and validation:

```java
@Service
public class TokenService {

    @Value("${api.security.token.secret}")
    private String secret;
    private final String issuer = "personal-catalog";

    public String generateToken(User user) {
        Algorithm algorithm = Algorithm.HMAC256(secret);
        return JWT.create()
                .withIssuer(issuer)
                .withSubject(user.getEmail())
                .withExpiresAt(generateExpirationDate())
                .sign(algorithm);
    }

    public String validateToken(String token) {
        Algorithm algorithm = Algorithm.HMAC256(secret);
        return JWT.require(algorithm)
                .withIssuer(issuer)
                .build()
                .verify(token)
                .getSubject();
    }

    private Instant generateExpirationDate() {
        return LocalDateTime.now().plusMinutes(2).toInstant(ZoneOffset.of("-03:00"));
    }
}

```

You have to create your JWT secret in application.properties:

```properties
api.security.token.secret=${JWT_SECRET:my-secret-key}
```

#### 13. Role-Based Access

To restrict access based on roles, you can use this in your security configuration:

```java
.requestMatchers(HttpMethod.POST, "/admin").hasRole("ADMIN")
```

#### 14. Implement Security Filter

Create a SecurityFilter class to intercept and validate JWT tokens on each request:

```java
@Component
public class SecurityFilter extends OncePerRequestFilter {

    private final TokenService tokenService;
    private final UserService userService;

    public SecurityFilter(TokenService tokenService, UserService userService) {
        this.tokenService = tokenService;
        this.userService = userService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = getTokenFromRequest(request);
        if (token != null) {
            String email = tokenService.validateToken(token);
            UserDetails user = userService.findByEmail(email);
            var auth = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
        filterChain.doFilter(request, response);
    }

    private String getTokenFromRequest(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");
        return (authorizationHeader != null) ? authorizationHeader.replace("Bearer ", "") : null;
    }
}
```

In this class we created a method called recuperaToken, which will be responsible to get the token from the header. Then we will validate the token, and if it is valid, we will create a UsernamePasswordAuthenticationToken, and set the user and authorities.

#### 15. Return JWT Token

Modify the login method to return a JWT token:

```java
var token = tokenService.generateToken((User) authentication.getPrincipal());
return ResponseEntity.ok(new TokenDto(token));
```

TokenDto:

```java
public record TokenDto(String token) {}
```
