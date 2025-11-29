const mongoose = require('mongoose');

// 定义鞋子的结构 (Schema)
// 这就像是告诉数据库：每一双鞋必须有这4个信息
const ProductSchema = new mongoose.Schema({
    name: { type: String, required: [true, "产品名称必填"] },
    price: {
        type: Number,
        required: true,
        min: [0, "价格不能为负数"] // 防止负数
    },
    // ...
});

// 导出这个模具
module.exports = mongoose.model('Product', ProductSchema);
