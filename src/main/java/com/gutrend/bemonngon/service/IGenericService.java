package com.gutrend.bemonngon.service;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.Optional;

public interface IGenericService<T> {
    List<T> findAll();
    void save(T t);
    Page<T> findAll(Pageable pageable);
    Optional<T> findById(Long id);
    void deleteById(Long id);
}
