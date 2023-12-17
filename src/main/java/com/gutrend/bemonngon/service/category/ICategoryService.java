package com.gutrend.bemonngon.service.category;

import com.gutrend.bemonngon.model.product.Category;
import com.gutrend.bemonngon.service.IGenericService;

public interface ICategoryService extends IGenericService<Category> {
    Boolean existsByName(String name);
}
