package com.autentia.demo.jwt.usuario;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class UsuarioController {

    private UsuarioRepository usuarioRepository;
    private BCryptPasswordEncoder bCryptPasswordEncoder; //cifrado Blowfish

    public UsuarioController(UsuarioRepository usuarioRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.usuarioRepository = usuarioRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @PostMapping("/users/")
    public void saveUsuario(@RequestBody Usuario user){
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        usuarioRepository.save(user);
    }
    @GetMapping("/users")
    public List<Usuario> getAllUsuarios(){
        return usuarioRepository.findAll();
    }
    @GetMapping("/users/{username}")
    public Usuario getUsuario(@PathVariable String username){
        return usuarioRepository.findByUsername(username);
    }
}
