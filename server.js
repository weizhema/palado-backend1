require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');   // 🔐 新零件：用来发令牌
const bcrypt = require('bcryptjs');    // 🔐 新零件：用来加密密码

// ⚠️ 请把这里的 Stripe Key 换成你自己的 Secret Key (sk_test_...)
const stripe = require('stripe')('sk_test_51SYdsIQr6341tjDEH6JwkKOiHprc8FSuRn8PyK2Ey6PJvM6C1ouOFXS0bzUAzyyfzCvkiMa0cC1glV9f6KanPJOp002foiGzlx');

// 引入模型
const Product = require('./models/Product');
const Order = require('./models/Order');

const app = express();
app.use(cors());
app.use(express.json());

// 🔐 密钥 (真实上线应该放在 .env 里，这里为了方便直接写了)
const SECRET_KEY = "palado_super_secret_key_888";

// 连接数据库
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ 数据库连接成功"))
    .catch(err => console.error("❌ 数据库错误:", err));

// ================= 安全系统 (Security) =================

// 1. 定义用户模型 (临时放在这里)
const UserSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: { type: String }
});
const User = mongoose.models.User || mongoose.model('User', UserSchema);

// 2. 初始化管理员接口 (运行一次即可)
// 访问: /api/init-admin 
app.get('/api/init-admin', async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash("123456", 10); // 密码是 123456
        await User.create({ username: "admin", password: hashedPassword });
        res.send("🎉 管理员创建成功！账号: admin, 密码: 123456");
    } catch (e) {
        res.send("管理员已存在，无需重复创建。");
    }
});

// 3. 登录接口 (前端 admin.html 会调用这个)
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    // 找人
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: "用户不存在" });

    // 对密码
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "密码错误" });

    // 发证 (Token)
    const token = jwt.sign({ id: user._id }, SECRET_KEY, { expiresIn: '2h' });
    res.json({ token, message: "登录成功" });
});

// 4. 门卫中间件 (保护后面的接口)
const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) return res.status(401).json({ error: "请先登录" });

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.user = decoded;
        next(); // 放行
    } catch (err) {
        res.status(401).json({ error: "无效的令牌" });
    }
};

// ================= 业务接口 (Business) =================

// 1. 获取产品 (公开)
app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find();
        res.json(products);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. 上架产品 (🔐 需要登录)
app.post('/api/products', authMiddleware, async (req, res) => {
    try {
        const newProduct = new Product(req.body);
        await newProduct.save();
        res.status(201).json(newProduct);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// 3. 下架产品 (🔐 需要登录)
app.delete('/api/products/:id', authMiddleware, async (req, res) => {
    try {
        await Product.findByIdAndDelete(req.params.id);
        res.json({ message: "删除成功" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 4. 获取订单 (🔐 需要登录 - 只有老板能看)
app.get('/api/orders', authMiddleware, async (req, res) => {
    try {
        const orders = await Order.find().sort({ date: -1 });
        res.json(orders);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 5. 提交订单 (公开 - 顾客用的，不用登录)
app.post('/api/orders', async (req, res) => {
    try {
        const newOrder = new Order(req.body);
        await newOrder.save();
        res.status(201).json({ message: "订单成功!", orderId: newOrder._id });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// 6. Stripe 支付 (公开)
app.post('/api/create-checkout-session', async (req, res) => {
    try {
        const { items } = req.body;
        if (!items || items.length === 0) return res.status(400).json({ error: "购物车为空" });

        const lineItems = items.map(item => ({
            price_data: {
                currency: 'usd',
                product_data: { name: item.name, images: item.img ? [item.img] : [] },
                unit_amount: Math.round(item.price * 100),
            },
            quantity: 1,
        }));

        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: lineItems,
            mode: 'payment',
            // ⚠️ 注意：这里最好写死你的 Vercel 地址，或者保持本地调试地址
            // 上线后建议改成: 'https://palado-shoes.vercel.app/index.html?status=success'
            success_url: 'https://palado-shoes.vercel.app/index.html?status=success',
            cancel_url: 'https://palado-shoes.vercel.app/index.html?status=cancel',
        });

        res.json({ id: session.id });
    } catch (error) {
        console.error("Stripe Error:", error);
        res.status(500).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 服务器运行中... 端口: ${PORT}`));