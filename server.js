require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

// 引入模型
const Product = require('./models/Product');
const Order = require('./models/Order'); // 👈 确保引入了订单模型

const app = express();
app.use(cors());
app.use(express.json());
const jwt = require('jsonwebtoken'); // 👈 新增
const bcrypt = require('bcryptjs');  // 👈 新增

const SECRET_KEY = "palado_super_secret_key_888"; // 🔐 密钥，真实项目要放 .env 里
// 连接数据库
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ 数据库连接成功"))
    .catch(err => console.error("❌ 数据库错误:", err));
// ==================== 1. 引入 Stripe ====================
// 把这里的字符串替换成你刚才发的那个 Key
const stripe = require('stripe')('sk_test_51SYdsIQr6341tjDEH6JwkKOiHprc8FSuRn8PyK2Ey6PJvM6C1ouOFXS0bzUAzyyfzCvkiMa0cC1glV9f6KanPJOp002foiGzlx');

// ... (这里是你原本的 express, mongoose 引入代码) ...

// ==================== 2. 添加支付接口 ====================
app.post('/api/create-checkout-session', async (req, res) => {
    try {
        const { items } = req.body; // 从前端传过来的购物车数组

        // 安全检查：如果购物车是空的
        if (!items || items.length === 0) {
            return res.status(400).json({ error: "购物车为空" });
        }

        // 把我们的购物车数据，转换成 Stripe 看得懂的格式
        const lineItems = items.map(item => ({
            price_data: {
                currency: 'usd', // 货币单位：美元
                product_data: {
                    name: item.name,
                    // 如果你的图片地址是 http 开头的真实网络图片，Stripe 支付页会显示出来
                    // 如果是本地图片，可以不填 images
                    images: item.img ? [item.img] : [],
                },
                // 注意：Stripe 的金额单位是“分”。比如 $10.00，这里要填 1000
                unit_amount: Math.round(item.price * 100),
            },
            quantity: 1, // 假设每个商品数量都是 1
        }));

        // 向 Stripe 发起请求，创建一个支付会话
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: lineItems,
            mode: 'payment',
            // 支付成功后，跳回你的前端首页，并带上 ?status=success
            // 注意：如果你本地前端端口不是 5500，请自行修改
            success_url: 'http://127.0.0.1:5500/index.html?status=success',
            cancel_url: 'http://127.0.0.1:5500/index.html?status=cancel',
        });

        // 把这个 session.id 返回给前端，前端拿它去跳转
        res.json({ id: session.id });

    } catch (error) {
        console.error("Stripe 错误:", error);
        res.status(500).json({ error: error.message });
    }
});

// ================= API 接口 =================
// ================= 安全相关 API =================

// 0. 初始化管理员 (运行一次后可注释掉)
// 访问 /api/init-admin 就会创建一个 admin/123456 的账号
app.get('/api/init-admin', async (req, res) => {
    const User = mongoose.model('User', new mongoose.Schema({
        username: { type: String, unique: true },
        password: { type: String }
    }));

    // 加密密码
    const hashedPassword = await bcrypt.hash("123456", 10);

    try {
        await User.create({ username: "admin", password: hashedPassword });
        res.send("管理员创建成功！账号: admin, 密码: 123456");
    } catch (e) {
        res.send("管理员可能已存在");
    }
});

// 1. 登录接口
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    // 临时定义 User 模型 (正规做法是单独文件)
    const User = mongoose.models.User || mongoose.model('User', new mongoose.Schema({
        username: String, password: String
    }));

    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: "用户不存在" });

    // 验证密码
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "密码错误" });

    // 登录成功，发 Token (这就好比发了一张身份证)
    const token = jwt.sign({ id: user._id }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token, message: "登录成功" });
});

// 2. 中间件 (门卫)
const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization; // 从请求头里拿 Token
    if (!token) return res.status(401).json({ error: "请先登录" });

    try {
        // 验证 Token 是否伪造
        const decoded = jwt.verify(token, SECRET_KEY);
        req.user = decoded;
        next(); // 放行
    } catch (err) {
        res.status(401).json({ error: "无效的令牌" });
    }
};

// ================= 修改原有的 API =================
// 1. 获取所有产品
app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find();
        res.json(products);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. 上架产品
app.post('/api/products', authMiddleware, async (req, res) => {
    try {
        const newProduct = new Product(req.body);
        await newProduct.save();
        res.status(201).json(newProduct);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// 3. 下架产品
app.delete('/api/products/:id', authMiddleware, async (req, res) => {
    try {
        await Product.findByIdAndDelete(req.params.id);
        res.json({ message: "删除成功" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 4. 🛒 顾客提交订单 (核心功能)
app.post('/api/orders', async (req, res) => {
    try {
        console.log("收到新订单:", req.body);
        const newOrder = new Order(req.body);
        await newOrder.save();
        res.status(201).json({ message: "订单成功!", orderId: newOrder._id });
    } catch (err) {
        console.error("❌ 订单保存失败:", err);
        res.status(400).json({ error: err.message });
    }
});

// 5. 👔 老板查看订单
app.get('/api/orders', authMiddleware, async (req, res) => {
    try {
        const orders = await Order.find().sort({ date: -1 });
        res.json(orders);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 6. 一键生成测试数据 (已修正数据格式！)
app.get('/api/seed', async (req, res) => {
    // 假产品
    const products = [
        { name: "Velocity X", price: 199, category: "running", img: "https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=500" },
        { name: "Urban Drift", price: 129, category: "casual", img: "https://images.unsplash.com/photo-1525966222134-fcfa99b8ae77?w=500" },
        { name: "Aero Glide", price: 249, category: "running", img: "https://images.unsplash.com/photo-1608231387042-66d1773070a5?w=500" }
    ];

    // 假订单 (这里修复了！字段名和 Order.js 保持一致)
    const orders = [
        {
            customerName: "Mike Ross",
            address: "123 Pearson St, New York",
            // items 必须是一个数组，里面放鞋子的信息
            items: [
                { name: "Velocity X", price: 199, img: "https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=500" }
            ],
            totalPrice: 199 // 对应 Order.js 里的 totalPrice
        },
        {
            customerName: "Rachel Zane",
            address: "456 Columbia Law, NYC",
            items: [
                { name: "Urban Drift", price: 129, img: "https://images.unsplash.com/photo-1525966222134-fcfa99b8ae77?w=500" }
            ],
            totalPrice: 129
        }
    ];

    try {
        await Product.deleteMany({});
        await Order.deleteMany({}); // 清空旧数据

        await Product.insertMany(products);
        await Order.insertMany(orders);

        res.json({ message: "🎉 数据已重置！产品和订单都修复了！" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 服务器运行中... 端口: ${PORT}`));