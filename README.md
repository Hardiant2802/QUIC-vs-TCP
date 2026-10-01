# QUIC-vs-TCP: hướng dẫn cài đặt và chạy thí nghiệm tuần 8

Hướng dẫn này dành cho Ubuntu/WSL2. Thực hiện các bước theo thứ tự: cài công cụ hệ thống, clone repo, vào thư mục repo, rồi mới chạy các bài đo.

## Cài đặt trên Ubuntu/WSL2

Mở terminal Ubuntu/WSL và cài các lệnh mạng, thư viện Python cùng công cụ biên dịch cần thiết cho bài migration:

```bash
sudo apt update
sudo apt install -y \
  git python3 python3-numpy python3-matplotlib \
  iproute2 ethtool iputils-ping openssl tcpdump tshark ca-certificates \
  curl tar make g++ pkg-config libgnutls28-dev libev-dev
```

## Clone kho mã nguồn

Clone kho mã nguồn rồi vào thư mục dự án. Các lệnh chạy thí nghiệm bên dưới đều thực hiện từ thư mục này:

```bash
git clone https://github.com/Hardiant2802/QUIC-vs-TCP.git ~/QUIC-vs-TCP
cd ~/QUIC-vs-TCP
```

Kho mã nguồn đã kèm Caddy, curl hỗ trợ HTTP/3 và dữ liệu thử nghiệm, nên các chế độ không cần biên dịch client migration có thể chạy ngay sau khi cài gói hệ thống.

## Chuẩn bị client bài migration

Chỉ cần bước này nếu chạy `migration` hoặc `all`. Helper tải ngtcp2 v1.16.0, kiểm tra SHA-256 và biên dịch `gtlsclient` trong repo. Chạy bằng tài khoản thường, không thêm `sudo`:

```bash
bash scripts/setup-week8-migration.sh
```

Các chế độ `baseline`, `loss` và `sweep` không cần bước này. Khi chạy phép đo, gọi runner bằng `sudo` để nó tạo network namespace và cấu hình `tc`.

Các lệnh dưới ghi đầy đủ tham số áp dụng cho từng bài. Kết quả nằm trong thư mục `--out`.
Khi chạy lại, đổi tên thư mục từ `-01` sang `-02`… vì script không ghi đè thư mục đã tồn tại.

Công cụ có 4 bài đo: `baseline` (tuần 3), `loss` (tuần 5), `migration` (tuần 6) và `sweep` (tuần 7). `all` chạy cả 4 bài.

## 1. Baseline — tuần 3

```bash
sudo bash scripts/run-experiment.sh \
  --mode baseline \
  --loss 0 \
  --delay 0ms \
  --rate unlimited \
  --runs 30 \
  --warmups 5 \
  --timeout 120 \
  --pcap first \
  --out data/week8/baseline-01
```

**Kết quả:** `data/week8/baseline-01/summary.csv` và đồ thị trong `baseline/`.
So sánh thời gian tải HTTP/2 và HTTP/3 khi không thêm trễ, mất gói hay giới hạn băng thông.

## 2. Mất gói và HOL blocking — tuần 5

```bash
sudo bash scripts/run-experiment.sh \
  --mode loss \
  --loss 0.5 \
  --delay 20ms \
  --rate 100mbit \
  --runs 30 \
  --warmups 0 \
  --timeout 120 \
  --pcap first \
  --out data/week8/hol-01
```

**Kết quả:** `data/week8/hol-01/summary.csv` và `loss/ecdf-loss-0.5.png`.
Đồ thị thể hiện phân bố thời gian hoàn tất các đối tượng tải thành công khi mất gói 0.5% mỗi chiều.
Xem kèm tỉ lệ thất bại trong CSV; dùng pcap để phân tích cơ chế HOL.

## 3. Chuyển đổi kết nối — tuần 6

Nếu chưa cài client chuyển mạng, chạy một lần:

```bash
bash scripts/setup-week8-migration.sh
```

```bash
sudo bash scripts/run-experiment.sh \
  --mode migration \
  --loss 0 \
  --delay 20ms \
  --migration-rate 20mbit \
  --switch-after 8 \
  --migration-after 10 \
  --disable-after 16 \
  --timeout 120 \
  --out data/week8/migration-01
```

**Kết quả:** `data/week8/migration-01/migration/loss-0/migration-summary.json` và pcap trong `h3/`, `h2/`, `h2-retry/`.
`verified: true` nghĩa là đủ bằng chứng: QUIC giữ kết nối và tải đủ tệp sau đổi mạng,
TCP cũ không tải đủ, còn lần kết nối TCP mới trên B tải đủ. `false` nghĩa là chưa đạt đủ các kiểm tra; xem chi tiết trong JSON và log.

Các mốc trên là đổi route sau 8 giây, QUIC đổi địa chỉ sau 10 giây kể từ khi bắt tay xong,
và tắt đường cũ sau 16 giây. Bài này chạy một cặp đối chiếu và bắt gói các lần tải; không dùng `--runs`, `--warmups`, `--pcap` hay `--rate`.

## 4. Khảo sát dải mất gói — tuần 7

```bash
sudo bash scripts/run-experiment.sh \
  --mode sweep \
  --loss-list 0,0.5,1,2,3,4,5,6,7,8,9,10 \
  --delay 20ms \
  --rate 100mbit \
  --runs 30 \
  --warmups 0 \
  --timeout 120 \
  --pcap first \
  --out data/week8/sweep-01
```

**Kết quả:** `data/week8/sweep-01/summary.csv`, `sweep/latency-and-failures.png` và các file `sweep/ecdf-loss-*.png`.
So sánh thời gian tải và tỉ lệ thất bại của hai giao thức theo từng mức mất gói từ 0% đến 10%.

## 5. Chạy toàn bộ các bài

```bash
sudo bash scripts/run-experiment.sh \
  --mode all \
  --loss 0.5 \
  --loss-list 0,0.5,1,2,3,4,5,6,7,8,9,10 \
  --delay 20ms \
  --rate 100mbit \
  --runs 30 \
  --warmups 0 \
  --timeout 300 \
  --pcap first \
  --migration-rate 20mbit \
  --switch-after 8 \
  --migration-after 10 \
  --disable-after 16 \
  --out data/week8/all-do-01
```

**Kết quả:** `data/week8/all-do-01/`, gồm bảng tổng hợp chung và bốn thư mục
`baseline/`, `loss/`, `sweep/`, `migration/`.
Baseline luôn dùng loss=0, delay=0ms; sweep dùng `--loss-list`; migration dùng `--migration-rate` và chỉ chạy một cặp đối chiếu.

## Đọc các file kết quả

| File | Dùng để làm gì? |
|---|---|
| `status.json` | Xem quy trình đã hoàn tất (`completed`), bị ngắt hoặc gặp lỗi. Hoàn tất quy trình vẫn có thể có lượt tải thất bại. |
| `validation.json`, `packet-checks.csv` | Xem số lượt thành công/thất bại, lỗi điều kiện đo và kiểm tra giải mã pcap. |
| `summary.csv` | Đọc min, p50, p95 và tỉ lệ thất bại của mỗi giao thức/điều kiện. |
| `runs.csv`, `objects.csv` | Xem chi tiết từng lượt đo và từng đối tượng tải. |
| `<mode>/*.png` | Đồ thị phân bố thời gian hoàn tất, p50/p95 và tỉ lệ thất bại. |
| `capture.pcap`, `tls.keys`, `packets.tsv` | Gói tin đã thu, khóa giải mã và bảng thông tin gói tin; nằm trong thư mục lượt đo có capture. |
| `curl.jsonl`, `run.json`, các file log | Dữ liệu gốc và thông tin để tìm nguyên nhân lỗi. |
| `migration/loss-*/migration-summary.json` | Kết quả kiểm tra riêng của bài chuyển đổi kết nối. |
| `config.json`, các file phiên bản, SHA-256, `netem-*.json` | Ghi lại tham số, môi trường, dữ liệu đầu vào và cấu hình mạng. |
| `cleanup.json` | Xác nhận đã dọn môi trường mạng tạm. |

**p50** là trung vị; **p95** là mốc mà 95% giá trị không vượt quá.
Phân vị và ECDF đối tượng chỉ tính các đối tượng thành công, nên luôn xem cùng tỉ lệ thất bại.
`--pcap first` chỉ lưu pcap lượt đo đầu mỗi giao thức/điều kiện; `--pcap all` lưu mọi lượt đo. Migration luôn bắt gói các lần tải.

<details>
<summary>Mặc định nếu không ghi tham số</summary>

| Tham số | Giá trị mặc định |
|---|---|
| `--mode` | `loss` |
| `--loss` | `0.5` (%) mỗi chiều |
| `--delay` | `20ms` mỗi chiều |
| `--rate` | `100mbit` mỗi chiều |
| `--loss-list` | `0,0.5,1,2,3,4,5,6,7,8,9,10` |
| `--runs` | `30` lượt/giao thức/điều kiện |
| `--warmups` | `0` lượt khởi động |
| `--timeout` | `120` giây |
| `--pcap` | `first` |
| `--migration-rate` | `20mbit` mỗi chiều |
| `--switch-after` | `8` giây từ lúc bắt đầu tiến trình tải |
| `--migration-after` | `10` giây từ lúc QUIC bắt tay xong |
| `--disable-after` | `16` giây từ lúc bắt đầu tiến trình tải |
| `--out` | Tự tạo `data/week8/<thời-gian>-<mã-riêng>` |
| `--dry-run` | Tắt; thêm cờ này để chỉ xem kế hoạch, không chạy đo |

Baseline luôn ép loss=0, delay=0ms. Sweep dùng `--loss-list`, không dùng `--loss`.
Nhóm tham số chuyển đổi kết nối chỉ áp dụng cho migration hoặc phần migration trong all.
Migration không dùng `--runs`, `--warmups`, `--pcap`, `--rate`, `--loss-list`.

</details>
