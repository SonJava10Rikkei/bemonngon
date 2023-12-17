package com.gutrend.bemonngon.model.product;

import com.gutrend.bemonngon.model.user.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;

import javax.persistence.*;
import java.time.Instant;

@Data
@AllArgsConstructor
@Entity
@Table(name = "categories")
@NoArgsConstructor(force = true)
public class Category {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NonNull
    @Column(unique = true)
    private String name;

    @NonNull
    private String type;

    private String avatar = "https://firebasestorage.googleapis.com/v0/b/nguyendanhson-9374f.appspot.com/o/Category_default.png?alt=media&token=32429ae4-ae06-43e9-a50d-5d797eb46932";

    @ManyToOne
    User user;
}
