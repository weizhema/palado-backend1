require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer'); // 📧 1. 引入成功

// Stripe 配置
const stripe = require('stripe')('sk_test_51SYdsIQr6341tjDEH6JwkKOiHprc8FSuRn8PyK2Ey6PJvM6C1ouOFXS0bzUAzyyfzCvkiMa0cC1glV9f6KanPJOp002foiGzlx');

// 引入模型
const Product = require('./models/Product');
const Order = require('./models/Order');

const app = express();
app.use(cors());
app.use(express.json());

const SECRET_KEY = "palado_super_secret_key_888";

// 连接数据库
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ 数据库连接成功"))
    .catch(err => console.error("❌ 数据库错误:", err));

// ================= 📧 2. 邮件服务配置 (关键新增) =================
// ⚠️ 徒儿，请在这里填入你的谷歌账号和 16位应用专用密码
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'maweizhe123@gmail.com', // 👈 替换这里
        pass: 'awlafcolwqxxcajj'    // 👈 替换这里 (不要有空格)
    }
});

// ================= 安全系统 =================

const UserSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: { type: String }
});
const User = mongoose.models.User || mongoose.model('User', UserSchema);

app.get('/api/init-admin', async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash("123456", 10);
        await User.create({ username: "admin", password: hashedPassword });
        res.send("🎉 管理员创建成功！账号: admin, 密码: 123456");
    } catch (e) {
        res.send("管理员已存在，无需重复创建。");
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: "用户不存在" });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "密码错误" });
    const token = jwt.sign({ id: user._id }, SECRET_KEY, { expiresIn: '2h' });
    res.json({ token, message: "登录成功" });
});

const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) return res.status(401).json({ error: "请先登录" });
    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ error: "无效的令牌" });
    }
};

// ================= 业务接口 =================

app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find();
        res.json(products);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/products', authMiddleware, async (req, res) => {
    try {
        const newProduct = new Product(req.body);
        await newProduct.save();
        res.status(201).json(newProduct);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

app.delete('/api/products/:id', authMiddleware, async (req, res) => {
    try {
        await Product.findByIdAndDelete(req.params.id);
        res.json({ message: "删除成功" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/orders', authMiddleware, async (req, res) => {
    try {
        const orders = await Order.find().sort({ date: -1 });
        res.json(orders);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ================= 📧 3. 提交订单 (升级版) =================
app.post('/api/orders', async (req, res) => {
    console.log("🔔 叮咚！有人敲门，收到了订单请求！");
    try {
        // A. 保存订单
        const newOrder = new Order(req.body);
        await newOrder.save();

        // B. 发送邮件逻辑
        const customerName = req.body.customerName || "顾客";
        // ✨ 新增：获取前端传来的 email
        // 如果前端没传，就发给老板(你自己)做保底
        const customerEmail = req.body.email || '你的测试接收邮箱@qq.com';

        const itemsHtml = req.body.items ? req.body.items.map(item => `<li>${item.name} - $${item.price}</li>`).join('') : "<li>商品详情见官网</li>";

        const mailOptions = {
            from: '"PALADO 履程" <你的谷歌邮箱@gmail.com>',
            to: customerEmail, // 👈 🎯 关键修改！这里不再是死值，而是活的！
            subject: `🎉 订单确认！谢谢你，${customerName}`,
            html: `
                <div style="font-family: sans-serif; padding: 20px; color: #333;">
                    <h1 style="color: #7380ec;">PALADO</h1>
                    <h2>👋 收到你的订单啦！</h2>
                    <p>亲爱的 <strong>${customerName}</strong>，</p>
                    <p>感谢您的信任！这封邮件已发送至：${customerEmail}</p>
                    <hr>
                    <h3>🧾 您的购物清单</h3>
                    <ul>${itemsHtml}</ul>
                    <p style="font-size:1.2rem; font-weight:bold;">总价: $${req.body.totalPrice}</p>
                    <p style="color:#999; margin-top:30px;">我们正在火速备货，请留意发货通知！🚚</p>
                </div>
            `
        };

        // C. 执行发送 (不阻塞主线程)
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.log("❌ 邮件发送失败:", error);
            } else {
                console.log('✅ 邮件已发送:', info.response);
            }
        });

        res.status(201).json({ message: "订单成功!", orderId: newOrder._id });

    } catch (err) {
        console.error(err);
        res.status(400).json({ error: err.message });
    }
});

// Stripe 支付
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