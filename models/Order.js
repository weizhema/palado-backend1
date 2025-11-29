const mongoose = require('mongoose');

const OrderSchema = new mongoose.Schema({
    customerName: { type: String, required: true },
    address: { type: String, required: true },

    // ⚠️ 关键修改：我们要存的是一个数组(items)，不是单个product
    items: { type: Array, required: true },

    // ⚠️ 关键修改：我们要存的是 totalPrice，不是 amount
    totalPrice: { type: Number, required: true },

    date: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Order', OrderSchema);