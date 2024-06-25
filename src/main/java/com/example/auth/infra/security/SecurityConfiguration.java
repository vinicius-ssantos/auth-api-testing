package com.example.auth.infra.security;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Autowired
    SecurityFilter securityFilter;


    // metodo para definir as configurações de segurança da aplicação
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity ) throws Exception {
        return httpSecurity
                .csrf(csrf-> csrf.disable() ) // define que a aplicação não vai usar csrf (csrf é um token que é enviado para o cliente e depois é enviado de volta para o servidor, para verificar se a requisição é válida)
                .sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // define que a aplicação não vai usar sessão

                .authorizeHttpRequests(authorize-> authorize
                        .requestMatchers(HttpMethod.POST,"/auth/login").permitAll()
                        .requestMatchers(HttpMethod.POST,"/auth/register").permitAll()
                        .requestMatchers(HttpMethod.POST,"/product").hasRole("ADMIN") // define que apenas usuários com a role de admin podem fazer requisições POST para /product
                        .anyRequest().authenticated()
                ) // define que qualquer requisição deve ser autenticada
                .addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class) // adiciona o filtro de segurança antes do filtro de autenticação

                .build();
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();

    }
}
