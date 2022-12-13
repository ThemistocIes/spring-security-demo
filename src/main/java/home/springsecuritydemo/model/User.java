package home.springsecuritydemo.model;

import lombok.Data;

import javax.persistence.*;

@Data
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "email", nullable = false)
    private String email;

    @Column(name = "password", nullable = false)
    private String password;

    @Column(name = "first_name", nullable = false)
    private String firstName;

    @Column(name = "last_name", nullable = false)
    private String lastName;

    @Column(name = "role", nullable = false)
    @Enumerated(value = EnumType.STRING)
    private Role role;

    @Column(name = "status", nullable = false)
    @Enumerated(value = EnumType.STRING)
    private Status status;
}
