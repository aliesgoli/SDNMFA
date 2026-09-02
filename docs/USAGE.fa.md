# اجرای آزمایش‌ها

[English](USAGE.md) | [معرفی پروژه](../README.fa.md)

## آماده‌سازی

محیط پایتون ساخته می‌شود، `.env` تکمیل می‌شود، migration پایگاه داده اجرا می‌شود و یک حساب فعال غیرآزمایشی آماده می‌شود. حسابی که campaign را آغاز می‌کند باید عامل‌های لازم برای Full MFA را داشته باشد.

```bash
python3.9 -m venv --system-site-packages venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install setuptools==67.8.0 wheel==0.45.1 pbr==5.11.1
./venv/bin/pip install --no-build-isolation -r requirements.txt
cp .env.example .env
chmod 600 .env
./venv/bin/python database/auto_migrator.py
./venv/bin/python admin/user_management.py
./venv/bin/python tools/preflight_check.py
```

Preflight باید با صفر failure تمام شود. secret کوتاه، تکراری یا نمونه پذیرفته نمی‌شود.

## بررسی طرح اجرا

گزینه `--dry-run` اندازه مطالعه را چاپ می‌کند و تغییری در PostgreSQL یا Mininet نمی‌دهد:

```bash
./venv/bin/python run_thesis_v2.py \
  --topology star-small --seed 20260822 --repetitions 5 \
  --phase complete --dry-run
```

با پنج تکرار، کل مطالعه سه‌توپولوژی شامل ۸۴۰ مشاهده احراز هویت، ۴٬۳۲۰ مشاهده مستقل شبکه و ۳۴٬۵۶۰ مشاهده زنجیره‌ای است.

## اجرای کامل

فرمان‌ها از ریشه مخزن اجرا می‌شوند. seed، تعداد تکرار و `.env` میان سه توپولوژی تغییر نمی‌کند.

```bash
sudo -E ./venv/bin/python run_thesis_v2.py \
  --topology star-small --seed 20260822 --repetitions 5 \
  --phase complete
```

```bash
sudo -E ./venv/bin/python run_thesis_v2.py \
  --topology tree-medium --seed 20260822 --repetitions 5 \
  --phase complete
```

```bash
sudo -E ./venv/bin/python run_thesis_v2.py \
  --topology partial-mesh-medium --seed 20260822 --repetitions 5 \
  --phase complete
```

اجراکننده migration، ‏preflight، ‏cohort مصنوعی، ‏Ryu، ‏Mininet، ‏checkpoint، پاک‌سازی و به‌روزرسانی گزارش را مدیریت می‌کند. بخش مستقل پیش از شروع taskها یک ورود موفق Full MFA می‌خواهد و پس از آن اجرای برنامه‌ریزی‌شده تعاملی نیست.

## اجرای جداگانه یک بخش

فقط ماتریس مستقل:

```bash
sudo -E ./venv/bin/python run_thesis_v2.py \
  --topology partial-mesh-medium --seed 20260822 --repetitions 5 \
  --phase factorial
```

فقط ماتریس زنجیره‌ای:

```bash
sudo -E ./venv/bin/python run_thesis_v2.py \
  --topology partial-mesh-medium --seed 20260822 --repetitions 5 \
  --phase chained
```

بخش زنجیره‌ای معمولاً پس از معتبرشدن ماتریس مستقل همان توپولوژی اجرا می‌شود.

## ادامه اجرا و پاک‌سازی

همان فرمان اصلی، فرمان ادامه نیز هست. taskهای معتبر تکمیل‌شده رد می‌شوند و taskهای ناتمام یا ثبت‌شده با `technical_error` دوباره اجرا می‌شوند.

اگر Mininet بیرون از اجراکننده متوقف شده باشد، پیش از ادامه namespaceهای باقی‌مانده پاک می‌شوند:

```bash
sudo mn -c
```

کد خروج `0` یعنی کار خواسته‌شده بدون خطای فنی باقی‌مانده تمام شده است. کد `2` یعنی مشاهده ثبت شده، ولی دست‌کم یک خطای فنی باقی مانده است. کد `130` نیز توقف اجرا را نشان می‌دهد.

نتیجه امنیتی و وضعیت فنی نباید با هم ترکیب شوند. `attack_success`، ‏`attack_blocked`، ‏`blocked_at_authentication`، ‏`availability_preserved` و `availability_degraded` مشاهده آزمایش‌اند؛ `not_evaluable` یک حذف فنی است.

## گزارش‌ها

Study ID چاپ‌شده توسط اجراکننده برای پروتکل، seed، تعداد تکرار و مجموعه توپولوژی ثابت می‌ماند.

```bash
./venv/bin/python analysis/article_report_v2.py --study-id STUDY_UUID
```

گزارش strict به داده معتبر کامل و صفر بودن خطاهای فنی نیاز دارد. هنگام اجرای مطالعه می‌توان گزارش تشخیصی ناقص را به‌طور صریح ساخت:

```bash
./venv/bin/python analysis/article_report_v2.py \
  --study-id STUDY_UUID --partial
```

داشبورد دوزبانه و پیوند دانلود خروجی‌ها در `reports/STUDY_UUID/index.html` قرار دارد. فایل `.env`، ‏logها، فایل‌های پایگاه داده، ‏PCAP و گزارش‌های اندازه‌گیری‌شده وارد Git نمی‌شوند.

## بررسی پیش از انتشار

```bash
./venv/bin/python -m unittest discover -s tests -v
./venv/bin/python tools/preflight_check.py
```

گزارش نهایی باید ۴٬۳۲۰ مشاهده معتبر شبکه، ۸۴۰ مشاهده معتبر احراز هویت، ۳۴٬۵۶۰ مشاهده معتبر زنجیره‌ای، هر سه توپولوژی و صفر خطای فنی را نشان دهد. ثبت بسته‌ها اختیاری است و با `--capture-pcap` فعال می‌شود؛ این گزینه زمان و فضای ذخیره‌سازی را به‌طور محسوسی افزایش می‌دهد.
