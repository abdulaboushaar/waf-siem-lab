#!/usr/bin/env python3
"""Generate the benign, bruteforce and enum payload sets as YAML.

The attack sets (sqli, xss, traversal) are NOT generated here. Those come from
PayloadsAllTheThings via build_attacks.py so that every attack payload keeps a
citation. This script owns only the traffic that has no upstream source: the
benign false-positive bait, the brute-force login attempts, and the enumeration
requests. See payloads/ATTACKS.md for the rest.

Run:  python3 gen_corpus.py
Writes benign.yaml, bruteforce.yaml, enum.yaml next to this file.
"""
import os
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))

# Real browser user agents. CRS at higher paranoia levels scores requests that
# carry no User-Agent or an obvious tool UA, so benign traffic must look real
# for the false-positive rate to mean anything.
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) "
    "Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
]


def entry(pid, endpoint, method, params, expected, headers=None):
    e = {
        "id": pid,
        "category": "benign" if pid.startswith("benign") else
                    ("bruteforce" if pid.startswith("brute") else "enum"),
        "endpoint": endpoint,
        "method": method,
        "params": params,
        "expected": expected,
        "source": "hand written",
    }
    if headers:
        e["headers"] = headers
    return e


def benign():
    out = []
    n = 0

    def add(endpoint, method, params, headers=None):
        nonlocal n
        n += 1
        out.append(entry(f"benign-{n:03d}", endpoint, method, params, "allow", headers))

    # 1. Searches containing an apostrophe. These are the classic SQLi false
    # positive. Several match real product names in the seed that carry an
    # apostrophe, so a WAF that blocks them blocks a paying customer.
    for q in ["O'Ryan", "Builder's Choice", "Editor's Pick", "Micro Center's",
              "d'angelo", "O'Neil", "it's a deal", "children's tablet",
              "men's headset", "O'Brien cables"]:
        add("/search.php", "GET", {"q": q})

    # 2. Searches containing a percent sign. The percent is the LIKE wildcard
    # and also the URL-encoding lead byte, so both the app and the WAF can
    # misread it.
    for q in ["20% off", "100% cotton sleeve", "50%", "%", "5% cashback",
              "up to 30% discount", "%pro%", "10 % restock fee", "0% APR",
              "%off%"]:
        add("/search.php", "GET", {"q": q})

    # 3. Ordinary English that happens to contain SQL keywords. A keyword based
    # rule with no syntax context flags these.
    for q in ["select a good monitor", "drop in ddr5 prices", "order by price",
              "union jack sticker", "insert coin arcade", "delete confirmation",
              "where is my order", "table saw", "having trouble picking",
              "group buy motherboard", "update my build", "join the newsletter",
              "create a wishlist", "alter my order", "grant warranty"]:
        add("/search.php", "GET", {"q": q})

    # 4. Comments containing <3 and the HTML comment close -->. Angle brackets
    # and --> trip XSS rules even in plainly benign text.
    hearts = ["love it <3", "great value --> buy it", "<3 <3 <3",
              "runs cool <3 quiet too", "5 stars --> recommend",
              "best price i found -->", "<3 this cooler",
              "arrived fast <3", "solid --> would buy again",
              "quiet fan <3 no complaints"]
    for i, body in enumerate(hearts, 1):
        add("/comment.php", "POST",
            {"product_id": (i % 30) + 1, "author": "shopper", "body": body})

    # 5. Spec downloads whose names contain spaces and dots. Benign filenames
    # the traversal rules and path normalisers can mangle.
    for f in ["spec sheet.txt", "rtx 5080 specs.txt", "read me.txt",
              "manual v2.1.txt", "ryzen 9800x3d.txt", "notes final.txt",
              "install guide.txt", "power draw.txt", "quick start.txt",
              "warranty info.txt"]:
        add("/download.php", "GET", {"file": f})

    # 6. Normal browsing carrying a real browser User-Agent.
    for i in range(20):
        ua = USER_AGENTS[i % len(USER_AGENTS)]
        if i % 3 == 0:
            add("/index.php", "GET", {}, {"User-Agent": ua})
        elif i % 3 == 1:
            add("/product.php", "GET", {"id": (i % 30) + 1}, {"User-Agent": ua})
        else:
            add("/search.php", "GET", {"q": "ddr5 32gb"}, {"User-Agent": ua})

    # 7. Plain browsing with no special headers.
    for q in ["rtx 5080", "nvme ssd", "am5 motherboard", "850w psu",
              "mechanical keyboard", "4k monitor", "air cooler",
              "wifi router", "ddr5", "pc case"]:
        add("/search.php", "GET", {"q": q})

    # 8. Legitimate logins with the correct credentials.
    for u, p in [("alice", "password1"), ("bob", "hunter2"),
                 ("admin", "admin123"), ("alice", "password1"),
                 ("bob", "hunter2")]:
        add("/login.php", "POST", {"username": u, "password": p})

    # 9. Ordinary product page views by id.
    for pid in range(1, 11):
        add("/product.php", "GET", {"id": pid})

    assert len(out) == 100, f"benign count is {len(out)}, expected 100"
    return out


def bruteforce():
    # 10 usernames x 3 passwords = 30 login attempts. expected: allow, because
    # NO single login attempt is a WAF-blockable event. The attack is the
    # VOLUME, and that is detected downstream in Wazuh by correlating a burst of
    # login_failed outcomes from one client, not by CRS returning 403.
    users = ["admin", "administrator", "root", "alice", "bob",
             "test", "guest", "user", "oracle", "postgres"]
    passwords = ["password", "123456", "admin"]
    out = []
    n = 0
    for u in users:
        for p in passwords:
            n += 1
            out.append(entry(f"brute-{n:03d}", "/login.php", "POST",
                             {"username": u, "password": p}, "allow"))
    assert len(out) == 30
    return out


def enum():
    # 20 requests for paths that do not exist. Same logic as brute force:
    # one 404 is not blockable, a burst of them is a scan and is caught by
    # correlation in the SIEM.
    paths = ["/wp-login.php", "/wp-admin/", "/.env", "/.git/config",
             "/phpmyadmin/", "/admin/config.php", "/backup.zip",
             "/server-status", "/.aws/credentials", "/config.php.bak",
             "/shell.php", "/xmlrpc.php", "/vendor/phpunit/phpunit/phpunit",
             "/actuator/health", "/api/v1/users", "/.ssh/id_rsa",
             "/wp-content/", "/cgi-bin/test.cgi", "/console", "/.svn/entries"]
    out = []
    for i, p in enumerate(paths, 1):
        out.append(entry(f"enum-{i:03d}", p, "GET", {}, "allow"))
    assert len(out) == 20
    return out


def dump(name, rows):
    path = os.path.join(HERE, name)
    with open(path, "w") as fh:
        yaml.safe_dump(rows, fh, sort_keys=False, allow_unicode=True, width=1000)
    print(f"wrote {path}  ({len(rows)} payloads)")


if __name__ == "__main__":
    dump("benign.yaml", benign())
    dump("bruteforce.yaml", bruteforce())
    dump("enum.yaml", enum())
