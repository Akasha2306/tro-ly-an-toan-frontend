const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
// Sử dụng cổng do dịch vụ Cloud cung cấp, mặc định là 3000 nếu chạy local
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === 'production';

// ==========================================
// 🛡️ LỚP BẢO MẬT 1: HELMET (Ẩn & bảo vệ thông tin máy chủ)
// ==========================================
app.use(helmet());
app.use(express.json());

// ==========================================
// ⚡ TỐI ƯU HIỆU NĂNG: NẠP DỮ LIỆU VÀO RAM KHI KHỞI ĐỘNG
// ==========================================
const phoneDataPath = path.join(__dirname, 'data', 'spam_phones.json');
const bankDataPath = path.join(__dirname, 'data', 'black_banks.json');
const productDataPath = path.join(__dirname, 'data', 'products.json');

// Khởi tạo các biến toàn cục lưu trữ cơ sở dữ liệu trên RAM
let SCAM_DATABASE = [];
let SCAM_BANK_DATABASE = [];
let PRODUCT_DATABASE = [];

function loadInitialData() {
    try {
        if (fs.existsSync(phoneDataPath)) {
            const phoneContent = fs.readFileSync(phoneDataPath, 'utf8');
            SCAM_DATABASE = JSON.parse(phoneContent);
            console.log(`⚡ [RAM] Đã nạp thành công ${SCAM_DATABASE.length} bản ghi số điện thoại.`);
        } else {
            console.warn(`⚠️ [Cảnh báo] Không tìm thấy file dữ liệu điện thoại tại: ${phoneDataPath}`);
        }

        if (fs.existsSync(bankDataPath)) {
            const bankContent = fs.readFileSync(bankDataPath, 'utf8');
            SCAM_BANK_DATABASE = JSON.parse(bankContent);
            console.log(`⚡ [RAM] Đã nạp thành công ${SCAM_BANK_DATABASE.length} bản ghi tài khoản ngân hàng.`);
        } else {
            console.warn(`⚠️ [Cảnh báo] Không tìm thấy file dữ liệu ngân hàng tại: ${bankDataPath}`);
        }

        if (fs.existsSync(productDataPath)) {
            const productContent = fs.readFileSync(productDataPath, 'utf8');
            PRODUCT_DATABASE = JSON.parse(productContent);
            console.log(`⚡ [RAM] Đã nạp thành công ${PRODUCT_DATABASE.length} bản ghi sản phẩm.`);
        } else {
            console.warn(`⚠️ [Cảnh báo] Không tìm thấy file dữ liệu sản phẩm tại: ${productDataPath}`);
        }
    } catch (error) {
        console.error("❌ Lỗi nghiêm trọng khi nạp dữ liệu vào RAM:", error.message);
    }
}

// Gọi hàm nạp dữ liệu ngay khi chạy ứng dụng
loadInitialData();

// ==========================================
// 🛡️ LỚP BẢO MẬT 2: CẤU HÌNH CORS ĐỘNG (DYNAMIC CORS) - ĐÃ KHÓA CHẶT
// ==========================================
const ALLOWED_ORIGINS = [
    'http://localhost:5500', 
    'http://127.0.0.1:5500',
    'https://akasha2306.github.io' // <--- Đã thêm trang GitHub Pages của bạn vào đây
];

// Nếu có cấu hình link frontend chính thức khác khi deploy
if (process.env.FRONTEND_URL) {
    ALLOWED_ORIGINS.push(process.env.FRONTEND_URL);
}

const corsOptions = {
    origin: function (origin, callback) {
        // 1. Cho phép các yêu cầu nội bộ không có origin (như curl hoặc các tool test nội bộ từ chính server)
        if (!origin) {
            return callback(null, true);
        }
        
        // 2. Kiểm tra xem trang web gửi yêu cầu có nằm trong danh sách ALLOWED_ORIGINS hay không
        // (Đã loại bỏ hoàn toàn 'null' để không ai có thể tự ý chạy file HTML cục bộ trên máy họ để gọi API của bạn)
        const isAllowed = ALLOWED_ORIGINS.some(allowed => origin.startsWith(allowed));
        if (isAllowed) {
            return callback(null, true);
        }

        // Từ chối và chặn đứng các truy cập từ các website lạ khác
        callback(new Error('🛡️ Chặn truy cập (CORS): Yêu cầu từ trang web này không được cho phép!'));
    },
    methods: 'GET', 
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// ==========================================
// 🛡️ LỚP BẢO MẬT 3: RATE LIMITING (Chặn Spam & Tấn công DoS)
// ==========================================
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // Chu kỳ 15 phút
    max: 100, // Tối đa 100 requests / 15 phút / 1 địa chỉ IP
    standardHeaders: true, 
    legacyHeaders: false, 
    message: {
        success: false,
        message: "🚨 Phát hiện hành vi bất thường: Bạn đã kiểm tra quá nhiều lần. Vui lòng thử lại sau 15 phút!"
    }
});
app.use('/api/', apiLimiter);

// ==========================================
// 📞 API 1: KIỂM TRA SỐ ĐIỆN THOẠI LỪA ĐẢO (Truy xuất trực tiếp từ RAM)
// ==========================================
app.get('/api/v1/check-phone', (req, res) => {
    const rawPhone = req.query.number;

    if (!rawPhone) {
        return res.status(400).json({ success: false, message: "Vui lòng cung cấp số điện thoại cần kiểm tra (?number=...)" });
    }

    // Làm sạch đầu vào
    let cleanPhone = rawPhone.replace(/[\/\s\.\-\(\)]/g, '');
    if (cleanPhone.startsWith('+84')) {
        cleanPhone = '0' + cleanPhone.slice(3);
    } else if (cleanPhone.startsWith('84') && cleanPhone.length > 10) {
        cleanPhone = '0' + cleanPhone.slice(2);
    }

    if (!/^\d+$/.test(cleanPhone) || cleanPhone.length > 15 || cleanPhone.length < 8) {
        return res.status(400).json({ success: false, message: "Định dạng số điện thoại không hợp lệ!" });
    }

    // TRUY XUẤT TỪ RAM
    const scamRecord = SCAM_DATABASE.find(item => item.phone === cleanPhone);

    if (scamRecord) {
        return res.status(200).json({
            success: true,
            data: {
                phone_number: cleanPhone,
                is_scam: true,
                details: {
                    scam_type: scamRecord.scam_type,
                    report_count: scamRecord.report_count,
                    severity: scamRecord.report_count > 20 ? "HIGH" : "MEDIUM"
                }
            }
        });
    } else {
        return res.status(200).json({
            success: true,
            data: { phone_number: cleanPhone, is_scam: false }
        });
    }
});

// ==========================================
// 💳 API 2: KIỂM TRA SỐ TÀI KHOẢN NGÂN HÀNG (Truy xuất trực tiếp từ RAM)
// ==========================================
app.get('/api/v1/check-bank', (req, res) => {
    const accQuery = req.query.account;

    if (!accQuery) {
        return res.status(400).json({ success: false, message: "Vui lòng cung cấp số tài khoản cần kiểm tra (?account=...)" });
    }

    const cleanAccount = accQuery.replace(/[^a-zA-Z0-9]/g, '').trim();

    if (cleanAccount.length > 20 || cleanAccount.length < 6) {
        return res.status(400).json({ success: false, message: "Độ gia hạn số tài khoản không hợp lệ!" });
    }

    // TRUY XUẤT TỪ RAM
    const scamRecord = SCAM_BANK_DATABASE.find(item => item.account === cleanAccount);

    if (scamRecord) {
        return res.status(200).json({
            success: true,
            data: {
                account_number: cleanAccount,
                is_scam: true,
                details: {
                    bank_name: scamRecord.bank,
                    scam_type: scamRecord.scam_type,
                    report_count: scamRecord.report_count,
                    severity: scamRecord.report_count > 50 ? "MỨC ĐỘ ĐỎ (RẤT NGUY HIỂM)" : "NGUY HIỂM"
                }
            }
        });
    } else {
        return res.status(200).json({
            success: true,
            data: { account_number: cleanAccount, is_scam: false }
        });
    }
});

// ==========================================
// 📦 API 3: KIỂM TRA SẢN PHẨM (Truy xuất trực tiếp từ RAM)
// ==========================================
app.get('/api/v1/check-product', (req, res) => {
    const rawName = req.query.name;

    if (!rawName) {
        return res.status(400).json({ success: false, message: "Vui lòng cung cấp tên sản phẩm cần kiểm tra (?name=...)" });
    }

    const cleanName = rawName.toLowerCase().trim();

    // TRUY XUẤT TỪ RAM (Tìm kiếm các sản phẩm chứa từ khóa)
    const matchedProducts = PRODUCT_DATABASE.filter(item => 
        item.name && item.name.toLowerCase().includes(cleanName)
    );

    return res.status(200).json({
        success: true,
        data: matchedProducts
    });
});

// ==========================================
// 🛡️ BỘ XỬ LÝ LỖI TRUNG TÂM
// ==========================================
app.use((err, req, res, next) => {
    console.error("🚨 Lỗi hệ thống:", err.message);
    res.status(500).json({ success: false, message: "Đã xảy ra lỗi xử lý trên hệ thống máy chủ!" });
});

app.listen(PORT, () => {
    console.log(`🔒 Máy chủ chạy ổn định tại cổng: ${PORT}`);
});