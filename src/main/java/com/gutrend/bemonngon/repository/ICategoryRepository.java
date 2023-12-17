package com.gutrend.bemonngon.repository;

import com.gutrend.bemonngon.model.product.Category;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ICategoryRepository extends JpaRepository<Category, Long> {
    Boolean existsByName(String name);
}
