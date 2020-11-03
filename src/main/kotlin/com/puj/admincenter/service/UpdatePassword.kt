package com.puj.admincenter.service

import com.puj.admincenter.domain.users.User
import com.puj.admincenter.dto.login.LoginDto
import com.puj.admincenter.dto.login.TokenDto
import com.puj.admincenter.repository.users.UserRepository

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import org.springframework.beans.factory.annotation.Value
import org.springframework.http.ResponseEntity
import org.springframework.http.HttpStatus
import org.springframework.security.crypto.bcrypt.BCrypt
import org.springframework.stereotype.Service
import java.util.stream.Collectors
import org.slf4j.LoggerFactory
import java.util.Calendar
import java.util.*

const bcrypt = require('bcrypt');
const saltRounds = 10;
const someOtherPlaintextPassword = 'not_bacon';

@Service
class UpdatePasswordService(val userRepository: UserRepository) {
    companion object {
        val logger = LoggerFactory.getLogger(UpdatePasswordService::class.java)!!
    }

   
    ///////////////////////////////////
    //PAra encriptar la contraseña
    ///////////////////////////////////

    bcrypt.genSalt(saltRounds, function(err, salt) {
        bcrypt.hash(PasswordDtp.password, salt, function(err, hash) {
            this.password=hash;
        });
    });
    //Tambien se puede hacer asi


    fun Update(PasswordDtp: PasswordDtp): ResponseEntity<*> {
        val user = userRepository.findUserByUserAndPassword(PasswordDtp.username,
                                                            PasswordDtp.password)
        if (user != null) {
            val userUpdate = userUpdate(
                        username = UpdatePasswordDto.username,
                        password = UpdatePasswordDto.newpassword
                        )
            val userSaved = userRepository.save(userUpdate)
            LOG.info("userUpdate ${PasswordDtp.username} Update with username ${userSaved.username}")
            
        } else {
            val message = "the user does not exist or is not enabled" 
            logger.error(message)
            ResponseEntity<String>(message,
                                   HttpStatus.NOT_FOUND)
        }
    }

  
}