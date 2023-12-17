package com.gutrend.bemonngon.controller;

import com.gutrend.bemonngon.config.Constant;
import com.gutrend.bemonngon.dto.response.ResponseMessage;
import com.gutrend.bemonngon.model.product.Category;
import com.gutrend.bemonngon.service.category.ICategoryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Optional;

@RestController
@RequestMapping("/category")
@CrossOrigin(origins = "*")
public class CategoryController {

    @Autowired
    private ICategoryService categoryService;

    @GetMapping
    public ResponseEntity<?> showListCategory() {
        return new ResponseEntity<>(categoryService.findAll(), HttpStatus.OK);
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> detailCategory(@PathVariable Long id) {
        Optional<Category> category = categoryService.findById(id);
        if (!category.isPresent()) {
            return new ResponseEntity<>(new ResponseMessage(Constant.ID_DOSE_NOT_EXIST), HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<>(category, HttpStatus.OK);
    }


    @GetMapping("/page")
    public ResponseEntity<?> pageCategory(@PageableDefault(size = 3) Pageable pageable) {
        return new ResponseEntity<>(categoryService.findAll(pageable), HttpStatus.OK);
    }


    @PostMapping("/create")
    public ResponseEntity<?> createCategory(@RequestBody Category category) {
        if (categoryService.existsByName(category.getName())) {
            return new ResponseEntity<>(new ResponseMessage(Constant.NAME_EXIST), HttpStatus.OK);
        }
        categoryService.save(category);
        return new ResponseEntity<>(new ResponseMessage(Constant.CREATE_SUCCESS), HttpStatus.OK);
    }


    @PutMapping("/update/{id}")
    public ResponseEntity<?> updateCategory(@PathVariable Long id, @RequestBody Category categoryNew) {
        Optional<Category> categoryOld = categoryService.findById(id);
        if (!categoryOld.isPresent()) {
            return new ResponseEntity<>(new ResponseMessage(Constant.ID_DOSE_NOT_EXIST), HttpStatus.NOT_FOUND);
        }
        boolean checkName = categoryNew.getName().equals(categoryOld.get().getName());
        boolean checkType = categoryNew.getType().equals(categoryOld.get().getType());
        boolean checkAvatar = false;

        if (!checkName) {
            if (categoryService.existsByName(categoryNew.getName())) {
                return new ResponseEntity<>(new ResponseMessage(Constant.NAME_EXIST), HttpStatus.OK);
            }
        }
        try {
            URL urlNew = new URL(categoryNew.getAvatar());
            URL urlOld = new URL(categoryOld.get().getAvatar());
            if (urlNew.equals(urlOld)) {
                checkAvatar = true;
            }
        } catch (MalformedURLException e) {
            return new ResponseEntity<>(new ResponseMessage(Constant.INVALID_URL_FORMAT), HttpStatus.NOT_FOUND);
        }
        if (checkName && checkType && checkAvatar) {
            return new ResponseEntity<>(new ResponseMessage(Constant.NO_CHANGE), HttpStatus.OK);
        }
        categoryNew.setId(categoryOld.get().getId());
        categoryService.save(categoryNew);
        return new ResponseEntity<>(new ResponseMessage(Constant.UPDATE_SUCCESS), HttpStatus.OK);
    }


    @DeleteMapping("/delete/{id}")
    public ResponseEntity<?> deleteCategory(@PathVariable Long id) {
        Optional<Category> category = categoryService.findById(id);
        if (!category.isPresent()) {
            return new ResponseEntity<>(new ResponseMessage(Constant.ID_DOSE_NOT_EXIST), HttpStatus.NOT_FOUND);
        }
        categoryService.deleteById(id);
        return new ResponseEntity<>(new ResponseMessage(Constant.DELETE_SUCCESS), HttpStatus.OK);
    }
}
