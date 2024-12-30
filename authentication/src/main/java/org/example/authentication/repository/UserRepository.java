package org.example.authentication.repository;

import org.example.authentication.model.User;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface UserRepository extends MongoRepository<User, String> {
    // Custom method to find a user by username
    Optional<User> findByUsername(String username);
}
