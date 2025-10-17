using System;
using System.Collections.Generic;
using SmtpGmailDemo.Models;

namespace SmtpGmailDemo {
    // Lưu toàn bộ hóa đơn, bao gồm danh sách item
    public class UserOrderViewModel {
        public string CustomerName {get;set;}       // Tên khách hàng
        public string InvoiceDate {get;set;}        // Ngày lập hóa đơn
        public string GrandTotal {get;set;}         // Tổng tiền
        public List<OrderItem> Items {get;set;}     // Danh sách các món hàng
    }
}