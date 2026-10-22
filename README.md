# PHP "php2shell" (CVE-2026-109618 / CVE-2026-109619): check and fix your servers

On 21 October 2026 the PHP project released fixes for two critical vulnerabilities (CVSS 9.2) that can let an **unauthenticated attacker run code on a web server** through ordinary HTTP requests ([announcement](https://news-web.php.net/php.announce/509), [advisory](https://www.php.net/index.php)). Exploitation attempts were seen in the wild before the release. The PHP project says updating is the only complete fix.

This repository has a small, read-only shell script, `check-php.sh`, that tells you whether the PHP on a Linux server is fixed, and summarises the log entries worth a look. Below it you'll find how to fix each common setup, and what the script can't tell you.

*Current release: [v1.0.0](https://github.com/g-seller/security-php-incident-26102026/releases/tag/v1.0.0), 22 October 2026. MIT licensed.*

## Am I affected?

Every PHP version older than these is affected:

| PHP branch | Fixed in |
|---|---|
| 8.5 | **8.5.12** |
| 8.4 | **8.4.27** |
| 8.3 | **8.3.36** |
| 8.2 | **8.2.35** |
| 8.6 (pre-release) | **8.6.0RC4** |
| 8.1 and older | No official release (end of life). The PHP project published source-only backports for 7.4, 8.0 and 8.1, and some Linux distributions ship backported packages. |

Linux distributions often fix a package **without changing its version number** (for example an older `7.4.33` package with the fix backported). That's why the script also reads the package changelog.

According to the advisory, the risk is highest with **Apache mod_php**, where remote code execution was demonstrated. **PHP-FPM, php-cgi, FrankenPHP and LiteSpeed** are also listed as at risk. The advisory doesn't discuss the CLI or PHP's built-in development server, but they use the same engine, so update them too.

## Requirements

- Linux server (any distribution) with `bash`, `awk`, `gzip` and the usual core tools; all are preinstalled almost everywhere.
- Root, or `sudo`, for the full check: reading `/var/log` and other users' processes. Without root you still get the version check.
- Optional: `curl` for `--url`, `docker` for `--docker`, `journalctl` on systemd hosts.
- No installation and no internet access needed on the server, apart from downloading the script once.

## Quick start

Download the released version and verify it hasn't been altered:

```bash
curl -fsSLO https://raw.githubusercontent.com/g-seller/security-php-incident-26102026/refs/tags/v1.0.0/check-php.sh
echo "b128f1534cd0d8b75e1b3b8765bb6d51e1319632e1d9c1ea9eb12578281784c1  check-php.sh" | sha256sum -c -
less check-php.sh            # read it first: never run scripts from the internet unseen
chmod +x check-php.sh
sudo ./check-php.sh
```

`sha256sum -c` must print `check-php.sh: OK`. On macOS, use `shasum -a 256 -c -`. If the server has no internet access, download the script on your machine and copy it over with `scp`.

Options:

| Command | What it does |
|---|---|
| `sudo ./check-php.sh` | PHP binaries and Apache mod_php on this host, running processes, standard logs |
| `sudo ./check-php.sh --docker` | also PHP inside every running Docker container |
| `./check-php.sh --url https://example.com` | remote check from anywhere, using the `X-Powered-By` header |
| `sudo ./check-php.sh --since 2026-10-01` | start the log review at another date (default: 2026-10-17) |
| `./check-php.sh --no-logs` | version check only |

Exit codes: `0` every PHP found is fixed, `1` something vulnerable was found, `2` nothing could be verified. You can use them in scripts or monitoring.

The script **changes nothing**: it only reads files, runs `php -v`, queries the package manager and, with `--docker`, runs `php -r 'echo PHP_VERSION;'` inside containers.

## Example output

A Debian 12 server with PHP-FPM and Apache mod_php, after updating (the log counts are illustrative):

```text
== PHP installed on this host
PASS  /usr/bin/php8.2 (cli): PHP 8.2.35 includes the fix
PASS  /usr/sbin/php-fpm8.2 (fpm-fcgi): PHP 8.2.35 includes the fix
PASS  /usr/lib/apache2/modules/libphp8.2.so (apache mod_php, highest risk): PHP 8.2.35 includes the fix
PASS  No running process uses a replaced PHP binary or module

== Logs since 2026-10-17 (symptoms to review, not proof either way)
INFO  Read 9 log files plus the systemd journal
INFO  48211 web requests logged since 2026-10-17
WARN  PHP worker crashes (segfaults / aborts). Memory-corruption exploits often crash workers while they retry:
    2026-10-21: 3
WARN  HTTP 500/502/503/504 responses (also caused by deploys, restarts and app bugs):
    2026-10-22: 14

Result: every PHP install found includes the fix. Remember to restart long-running PHP processes after updating.
```

### Reading the result

| Line | Meaning | What to do |
|---|---|---|
| `PASS` | This PHP includes the fix. | Nothing. |
| `FAIL` | This PHP is vulnerable, or a process still runs the old code. | Update (see below), restart, run the script again. |
| `WARN` | Something in the logs is worth a look. It is **not** proof of an attack. | Compare the dates with your deploys and restarts. Unexplained spikes, especially worker crashes or "out of memory before any script ran" on 17–22 October, deserve a closer look at that day's logs. |
| `????` | The script couldn't check something (no access, unknown format). | Run as root, or check that part by hand. |
| `INFO` | Context only. | Nothing. |

In the example above, the 14 errors on 22 October match a deploy that day, and the 3 crashes on 21 October would be worth checking in the PHP-FPM log.

## What the script checks

1. **Every PHP on the host** in the usual locations: distribution packages (`/usr/bin/php8.x`, `/usr/sbin/php-fpm8.x`, `/usr/lib/cgi-bin`), `/usr/local` builds, Remi (`/opt/remi`), cPanel EasyApache (`/opt/cpanel`) and Plesk (`/opt/plesk/php`). It compares each version with the table above.
2. **Apache mod_php** (`libphp*.so`), whose version comes from its package.
3. **Distribution backports**: if the version number looks vulnerable, it reads the package changelog (`dpkg`/`apt` systems and `rpm` systems) for the two CVE IDs.
4. **Processes that were never restarted**: after an update, PHP-FPM or Apache keep running the old, vulnerable code until restarted. Linux marks such processes, and the script flags them.
5. **Docker containers** (`--docker`): the PHP version inside each running container.
6. **Logs since 17 October**, the first exploitation attempt reported. It reads nginx, Apache/httpd, PHP-FPM, PHP error logs, `kern.log`/`messages` and the systemd journal, including rotated and `.gz` files. Per day, it counts:
   - PHP running **out of memory before any script ran** (`in Unknown on line 0`). The first vulnerability needs exactly this condition, usually triggered with a crafted upload request.
   - **PHP worker crashes** (segfaults, aborts). Exploit attempts against memory bugs often crash workers.
   - out-of-memory errors inside scripts, and execution timeouts (fatal errors the second vulnerability can use)
   - HTTP **500/502/503/504** and **413** (request too large) responses

The log findings are **symptoms to review, not a verdict**. A deploy, an app bug or a heavy report page produces the same entries. Look for spikes you can't explain, especially around 17–22 October.

## How to fix it

Whatever your setup, **restart PHP after updating** (PHP-FPM, Apache, or recreate the container). Then run the script again.

**Debian / Ubuntu (distribution packages)**
```bash
sudo apt update && sudo apt install --only-upgrade 'php*'
sudo systemctl restart 'php*-fpm' apache2     # whichever you use
```
Debian 12 already ships `8.2.35-1~deb12u1`. For other releases, check your distribution's security tracker or run the script, which reads the changelog for you.

**deb.sury.org (Ondřej Surý) or Remi repositories:** update as above (`apt` or `dnf`). These repositories ship the upstream releases, so you should see the fixed version number.

**RHEL / AlmaLinux / Rocky / Fedora**
```bash
sudo dnf update 'php*'
rpm -q --changelog php-common | grep -E 'CVE-2026-10961[89]'   # confirms a backport
sudo systemctl restart php-fpm httpd
```

**Docker (official `php` images):** use an exact, fixed tag such as `php:8.3.36-fpm` or `php:8.2.35-apache`, and rebuild with a fresh pull:
```bash
docker compose build --pull && docker compose up -d
```
A floating tag such as `php:8.3-fpm` stays cached on the host, so a plain rebuild can keep the old, vulnerable PHP for months without any warning. Pinning the exact version makes the update visible and repeatable. Recreating the container (`up -d`) is what actually replaces the running PHP.

**Shared hosting / managed platforms (cPanel, Plesk, CloudLinux, PaaS):** select the newest PHP release in your control panel, or ask your provider whether their builds include the fix for CVE-2026-109618 and CVE-2026-109619. You usually can't run this script there, but `--url` works from your own machine if the site sends `X-Powered-By`.

**Built from source:** build the fixed release from [php.net/downloads](https://www.php.net/downloads), or apply the official backport branches for 7.4–8.1.

**End-of-life PHP (8.1 or older):** treat this as the moment to upgrade. Until you can, use a vendor with long-term support or the source backports.

### If you can't update today

The advisory lists measures that **reduce the risk but don't remove it**. Set them in `php.ini` or the FPM pool, not with `ini_set()`, then restart PHP:

```ini
session.upload_progress.enabled = 0      ; recommended even after updating, if you don't use it
; PHP 8.5 only:
fatal_error_backtraces = 0
```

The advisory also suggests:
- a conservative `post_max_size` and `upload_max_filesize`, with request-size limits enforced at the web server or proxy;
- blocking `multipart/form-data` requests where your application has no uploads;
- `memory_limit = -1`, set administratively (`php_admin_value`) together with a container or cgroup memory limit. Read the advisory before doing this, because it has side effects.

See [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) for the full list.

## Limitations: read before relying on the result

- **It checks versions, not exploitability.** It doesn't attack your server or try to trigger the bugs. A PASS means the installed PHP contains the fix, nothing more.
- **It is not a compromise detector.** A server that was attacked before you patched can still have a backdoor after the update. The log summary shows symptoms, but a clean result doesn't prove nothing happened, and a WARN doesn't prove an attack. As of 22 Oct 2026 no public indicators of compromise exist for these CVEs. If you suspect a break-in, keep the logs, don't wipe the server yet, and get professional help.
- **Backport detection depends on the changelog naming the CVE IDs.** Most distributions do this. Some vendor builds (control-panel PHP, CloudLinux alt-php, appliances) may not, and the script then reports FAIL although the build is fixed. Confirm with your vendor.
- **It only finds PHP in the standard locations** listed above. Custom builds in other paths, PHP inside other runtimes (FrankenPHP and RoadRunner binaries, embedded PHP) and Windows servers aren't covered. Check those with `php -v` or `phpinfo()`.
- **Docker:** only running containers that have `sh` and a `php` binary in their `PATH` are checked. Stopped containers, images, Kubernetes pods and distroless images aren't. A fixed image only helps once the container has been rebuilt and recreated.
- **The remote check (`--url`)** depends on the `X-Powered-By: PHP/x.y.z` header. Many servers hide it, proxies and CDNs often strip it, and it can't show distribution backports. A missing header proves nothing, so check on the server itself.
- **Restart detection is Linux-only** and needs root to see other users' processes.
- **Logs:**
  - Only the standard locations and formats are parsed (combined access log, default nginx/Apache/PHP-FPM/PHP error formats, syslog, journald). Custom log formats or other paths are skipped.
  - Request bodies are never logged, so the uploads that carry the attack aren't visible.
  - Logs that were rotated away, or that live inside containers (`docker logs`), can't be reviewed. The script warns when the logs don't reach back far enough.
  - On classic syslog lines without a year, the current year is assumed.
- **The fixed-version table is hard-coded** for this incident. For later PHP security releases, update the table or check [php.net](https://www.php.net/ChangeLog-8.php).

## Sources

- PHP announcement: <https://news-web.php.net/php.announce/509>
- PHP security advisory and fixed releases (21 Oct 2026): <https://www.php.net/index.php>, <https://www.php.net/ChangeLog-8.php>
- CVE-2026-109618, RCE via OOM corruption: <https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w>
- CVE-2026-109619, RCE via stale global state: <https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp>
- CISA alert: <https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching>

## Reporting problems and contributing

- **The script misreports your setup** (a PHP it doesn't find, a wrong FAIL for a fixed vendor build, a log format it doesn't parse): open an issue with your distribution and version, how PHP is installed, and the relevant output lines. Remove host names, IPs and paths you don't want public first.
- **Pull requests are welcome**, for example more install locations or log formats. Keep the script read-only and dependency-free.
- **Don't post details of a live compromise** in a public issue. Contact your hosting provider or a security incident response service instead.
- **Report vulnerabilities in PHP itself** to the PHP project, as described in its [security policy](https://github.com/php/php-src/security/policy), not here.

## License and disclaimer

[MIT License](LICENSE): you may use, copy, modify and redistribute the script and this guide, also commercially, as long as the copyright notice is kept.

Provided **as is, without warranty**. The script is read-only, but you run it at your own risk, and a PASS doesn't guarantee your server is safe. The information reflects the PHP advisory of 21 October 2026. Always check [php.net](https://www.php.net/) for the latest releases.
