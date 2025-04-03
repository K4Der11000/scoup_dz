import requests
from bs4 import BeautifulSoup
import re
from PIL import Image
import random
import time

# معجم النصوص
texts = {
    "en": {
        "loading_logo": "Loading logo...",
        "subdomains_found": "Subdomains found for",
        "subdomains_report": "Subdomains Report",
        "error_loading_logo": "Error loading the logo: {error}",
        "subdomains_saved": "Subdomains saved in HTML file: subdomains.html",
        "enter_domain": "Enter the domain name (e.g., example.com): ",
        "https_check": "Checking {subdomain} for vulnerabilities...",
        "https_support": "Supports HTTPS properly.",
        "no_https_support": "Does not support HTTPS properly or connection was refused.",
        "http_check_failed": "Failed to connect to HTTP: {error}",
        "robots_check": "The domain does not have a robots.txt file or failed to access it.",
    },
    "ar": {
        "loading_logo": "جارٍ تحميل اللوجو...",
        "subdomains_found": "تم العثور على النطاقات الفرعية لـ",
        "subdomains_report": "تقرير النطاقات الفرعية",
        "error_loading_logo": "حدث خطأ في تحميل اللوجو: {error}",
        "subdomains_saved": "تم حفظ النطاقات الفرعية في ملف HTML: subdomains.html",
        "enter_domain": "أدخل اسم النطاق (مثال: example.com): ",
        "https_check": "فحص {subdomain} للثغرات الأمنية...",
        "https_support": "يدعم HTTPS بشكل صحيح.",
        "no_https_support": "لا يدعم HTTPS بشكل صحيح أو تم رفض الاتصال.",
        "http_check_failed": "فشل في الاتصال بـ HTTP: {error}",
        "robots_check": "النطاق لا يحتوي على ملف robots.txt أو فشل في الوصول إليه.",
    }
}

# اختيار اللغة (افتراضيًا الإنجليزية)
language = "ar"  # يمكن تغييره إلى "en" للغة الإنجليزية

# دالة لاختيار النص بناءً على اللغة
def translate(key, **kwargs):
    text = texts[language].get(key, key)
    return text.format(**kwargs) if kwargs else text

# تحميل وعرض اللوجو
def display_logo():
    try:
        print(translate("loading_logo"))
        logo = Image.open("kader11000_logo.png")  # تأكد من أن الصورة موجودة في نفس المسار
        logo.show()
    except Exception as e:
        print(translate("error_loading_logo", error=e))

# عرض اللوجو عند بدء السكريبت
display_logo()

# دالة لتخزين النطاقات الفرعية في ملف HTML
def save_to_html(domain, subdomains):
    html_content = f"""
    <html>
    <head>
        <title>نطاقات فرعية لـ {domain}</title>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; }}
            h1 {{ color: #333; }}
            ul {{ list-style-type: none; padding: 0; }}
            li {{ background-color: #fff; margin: 5px; padding: 10px; border: 1px solid #ccc; }}
        </style>
    </head>
    <body>
        <h1>النطاقات الفرعية لـ {domain}</h1>
        <ul>
    """
    
    for subdomain in subdomains:
        html_content += f"<li>{subdomain}</li>"
    
    html_content += """
        </ul>
    </body>
    </html>
    """
    
    with open("subdomains.html", "w", encoding="utf-8") as file:
        file.write(html_content)
    print(translate("subdomains_saved"))

# دالة للتحقق من صحة النطاقات الفرعية
def validate_subdomains(subdomains, domain):
    valid_subdomains = []
    for subdomain in subdomains:
        if re.match(r'^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$', subdomain):
            valid_subdomains.append(subdomain)
        else:
            print(f"النطاق الفرعي غير صالح: {subdomain}")
    return valid_subdomains

# دالة لفحص الثغرات الأمنية
def security_check(subdomain, proxy=None):
    report = {}
    print(translate("https_check", subdomain=subdomain))
    
    try:
        https_response = requests.get(f"https://{subdomain}", proxies=proxy, timeout=5)
        if https_response.status_code == 200:
            report['https'] = translate("https_support")
        else:
            report['https'] = translate("no_https_support")
    except requests.exceptions.RequestException as e:
        report['https'] = f"فشل في الاتصال بـ HTTPS: {e}"
    
    try:
        response = requests.head(f"http://{subdomain}", proxies=proxy, timeout=5)
        headers = response.headers
        if 'X-Content-Type-Options' not in headers:
            report['X-Content-Type-Options'] = "يُفتقر إلى رأس الأمان 'X-Content-Type-Options'."
        if 'Strict-Transport-Security' not in headers:
            report['Strict-Transport-Security'] = "يُفتقر إلى رأس الأمان 'Strict-Transport-Security'."
        if 'X-XSS-Protection' not in headers:
            report['X-XSS-Protection'] = "يُفتقر إلى رأس الأمان 'X-XSS-Protection'."
        else:
            report['headers'] = "رؤوس الأمان سليمة."
    except requests.exceptions.RequestException as e:
        report['http'] = translate("http_check_failed", error=e)
    
    try:
        robots_url = f"http://{subdomain}/robots.txt"
        robots_response = requests.get(robots_url, proxies=proxy, timeout=5)
        if robots_response.status_code == 200:
            report['robots.txt'] = "النطاق يحتوي على ملف robots.txt."
        else:
            report['robots.txt'] = translate("robots_check")
    except requests.exceptions.RequestException:
        report['robots.txt'] = translate("robots_check")
    
    return report

# دالة لاستخراج النطاقات الفرعية من crt.sh
def get_subdomains_from_crtsh(domain, proxy=None):
    url = f"https://crt.sh/?q=%25.{domain}"
    response = requests.get(url, proxies=proxy)
    
    if response.status_code == 200:
        print(f"\n{translate('subdomains_found')} {domain}:")
        soup = BeautifulSoup(response.text, 'html.parser')
        subdomains = set(re.findall(r'\S+\.{}$'.format(re.escape(domain)), soup.text))
        
        if subdomains:
            valid_subdomains = validate_subdomains(subdomains, domain)
            if valid_subdomains:
                all_reports = {}
                for subdomain in valid_subdomains:
                    print(subdomain)
                    report = security_check(subdomain, proxy)
                    all_reports[subdomain] = report
                
                print("\n--- " + translate("subdomains_report") + " ---")
                for subdomain, report in all_reports.items():
                    print(f"\nالنطاق الفرعي: {subdomain}")
                    for key, value in report.items():
                        print(f"{key}: {value}")
                
                save_to_html(domain, valid_subdomains)
            else:
                print("لم يتم العثور على نطاقات فرعية صالحة.")
        else:
            print("لم يتم العثور على نطاقات فرعية.")
    else:
        print(f"حدث خطأ أثناء الاتصال بـ crt.sh: {response.status_code}")

# دالة لاختيار بروكسي عشوائي
def get_random_proxy():
    proxies = update_proxies_list()
    return {"http": random.choice(proxies), "https": random.choice(proxies)}

# دالة لتحديث قائمة البروكسيات
def update_proxies_list():
    proxies = []
    
    try:
        proxy_url = "https://www.proxy-list.download/api/v1/get?type=https"
        response = requests.get(proxy_url, timeout=5)
        
        if response.status_code == 200:
            proxies = response.text.splitlines()
            print(f"تم تحديث قائمة البروكسيات بنجاح. عدد البروكسيات: {len(proxies)}")
        else:
            print(f"فشل في تحميل البروكسيات من المصدر، سيتم استخدام البروكسيات الافتراضية.")
    except requests.exceptions.RequestException as e:
        print(f"حدث خطأ أثناء محاولة تحديث البروكسيات: {e}")
    
    if not proxies:
        proxies = [
            "http://123.123.123.123:8080",
            "http://234.234.234.234:8080",
        ]
    return proxies

# مثال على استخدام السكريبت
domain = input(translate("enter_domain"))

proxy = get_random_proxy()

get_subdomains_from_crtsh(domain, proxy)
