using System;

namespace SmtpGmailDemo.Models
{
    // Lưu thông tin từng món hàng trong hóa đơn
    public class OrderItem
    {
        public int? Index {get;set;}             // STT trong bảng
        public string? ItemName {get;set;}       // Tên vật phẩm
        public string? Unit {get;set;}           // Đơn vị tính
        public int? Quantity {get;set;}          // Số lượng
        public string? Price {get;set;}          // Đơn giá (chuỗi để dễ format tiền)
        public string? Total {get;set;}          // Thành tiền
    }
}