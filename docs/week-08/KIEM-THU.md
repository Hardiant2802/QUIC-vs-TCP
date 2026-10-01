# Kiểm thử script tuần 8 ngày 19 tháng 9 năm 2026

> Đây là biên bản của phiên bản cũ ngày 19/09/2026. Từ 27/09/2026, công cụ bỏ chế độ `handshake`; `all` chỉ chạy baseline, loss, sweep và migration. Tuần 4 phân tích pcap baseline bằng Wireshark. Các số lượt bên dưới là kết quả lịch sử, không mô tả lịch chạy của phiên bản hiện tại.

## Lần xác nhận cuối

```bash
sudo bash scripts/run-experiment.sh \
  --mode all --runs 1 --loss 0 --loss-list 0,1 --timeout 120 \
  --out data/week8/qa-final-20260919
```

Kết quả: mã thoát 0; `status.json` ghi `completed`; 10/10 lượt đo thông thường hoàn tất,
không có lượt sai giao thức/số kết nối, không có pcap thiếu luồng giải mã.
Các file gốc, thống kê và đồ thị nằm tại `data/week8/qa-final-20260919`.

| Kiểm tra | Kết quả |
|---|---|
| Baseline, handshake, loss và sweep (0%, 1%) | Đều chạy và tạo dữ liệu/phân tích |
| HTTP/2 | TLS 1.2, ALPN h2, tải trên một kết nối |
| HTTP/3 | QUIC, đủ stream yêu cầu trong pcap |
| QUIC chuyển mạng | 10.0.1.1:37167 → 10.0.2.1:51889, cùng Connection Number 0 |
| Xác thực đường QUIC | Có PATH_CHALLENGE và PATH_RESPONSE; không có Initial mới từ B |
| Tệp QUIC | Đủ 67108864 byte, SHA-256 trùng tệp gốc, không có lỗi client |
| TCP cũ khi tắt mạng A | Mã 28, chỉ nhận 37486592 byte |
| TCP kết nối lại trên B | Có SYN mới, TLS 1.2/ALPN h2, tải đủ và SHA-256 trùng |
| Dọn môi trường | `cleanup.json` xác nhận xóa cả hai namespace; không còn namespace của lần chạy |

Tệp gốc và tệp tải đủ có SHA-256:

```text
bc54c12dce3585371609f109deb4fd9769824d6eeb8b7496d1b6a6f8ccb9c2db
```

## Các kiểm tra bổ sung trong quá trình phát triển

- Mất gói 100%, timeout 2 giây: 0/40 đối tượng thành công, tỉ lệ thất bại 100%; không tạo phân vị giả cho dữ liệu rỗng. Kết quả tại `data/week8/qa-total-loss-01`.
- Ctrl+C trong khi tải: mã 130, trạng thái `interrupted`, tiến trình và namespace được dọn. Kết quả tại `data/week8/qa-interrupt-final`.
- Từ chối thư mục kết quả đã tồn tại, cấu hình cũ giữ nguyên.
- Từ chối loss ngoài khoảng, NaN, delay thiếu đơn vị, rate bằng 0, số lượt không hợp lệ, dải loss trùng và các mốc migration không đúng thứ tự.
- `--dry-run` không tạo môi trường; baseline đưa loss/delay về 0 dù người dùng nhập giá trị khác.
- Dữ liệu giả để kiểm tra bộ phân tích: loại lượt dùng sai HTTP version và lượt có nhiều kết nối; giữ lượt đối chứng hợp lệ.
- `bash -n` và biên dịch cú pháp Python đều đạt; helper cài migration nhận ra bản đã cài.

Một bài thử với `--migration-rate 40mbit --switch-after 1 --migration-after 2 --disable-after 3`
gặp `ERR_INTERNAL` từ client ngtcp2, mặc dù mã thoát client là 0. Bộ kiểm tra phát hiện tệp thiếu,
đánh dấu migration chưa đạt thay vì kết luận thành công. Dữ liệu chẩn đoán tại `data/week8/qa-verified-20260919`.
Các thư mục QA trung gian được giữ lại; dùng `qa-final-20260919` làm lần xác nhận bản cuối.

Đây là kiểm tra chức năng với ít lượt, không phải bộ số liệu đủ để kết luận ưu thế hiệu năng.
Khi đo chính thức, chạy 30 lượt và xem cả phân vị thời gian lẫn tỉ lệ thất bại.

## Kiểm tra bản bỏ chế độ handshake — 27/09/2026

- Kiểm tra cú pháp Python, danh sách `--help`, kế hoạch `all` và việc từ chối `--mode handshake`: đạt.
- Chạy baseline 1 lượt/giao thức, không làm nóng, không thêm mất gói/trễ, không giới hạn băng thông: 2/2 lượt hoàn tất.
- Mỗi giao thức tải 20 tệp và giải mã đủ 20 stream yêu cầu. Có `capture.pcap`, `tls.keys`, `packets.tsv`; kiểm tra thấy TCP SYN và QUIC Initial.
- `cleanup.json` ghi dọn namespace thành công, không có lỗi.
- Kết quả: `data/week8/qa-baseline-pcap-20260927`.
- Lần này chỉ chạy thực tế baseline và kiểm tra kế hoạch `all`; không chạy lại các bài loss, sweep hoặc migration.
