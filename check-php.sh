#!/usr/bin/env bash
# Checks whether this server runs a PHP release that fixes CVE-2026-109618 and
# CVE-2026-109619 ("php2shell", https://news-web.php.net/php.announce/509), and
# summarises PHP crash, out-of-memory and HTTP 5xx entries in standard log
# locations so you can review them. Read-only: it changes nothing.
#
# Usage:
#   sudo ./check-php.sh                         # local PHP binaries, mod_php, standard logs
#   sudo ./check-php.sh --docker                # also PHP inside running Docker containers
#   ./check-php.sh --url https://example.com    # remote: version from the X-Powered-By header
#   sudo ./check-php.sh --since 2026-10-01      # start of the log window (default 2026-10-17)
#   ./check-php.sh --no-logs                    # version check only
#
# Exit codes: 0 every PHP found is fixed, 1 a vulnerable PHP was found,
#             2 no PHP could be verified.

set -uo pipefail

SINCE="2026-10-17"
DOCKER=0
LOGS=1
URLS=""
CVES="CVE-2026-109618|CVE-2026-109619"

while [ $# -gt 0 ]; do
    case "$1" in
        --since) SINCE="$2"; shift 2 ;;
        --docker) DOCKER=1; shift ;;
        --url) URLS="$URLS $2"; shift 2 ;;
        --no-logs) LOGS=0; shift ;;
        -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown argument: $1 (see --help)" >&2; exit 2 ;;
    esac
done
if [[ ! "$SINCE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then echo "--since must be YYYY-MM-DD" >&2; exit 2; fi

if [ -t 1 ]; then RED=$'\e[31m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; BOLD=$'\e[1m'; RESET=$'\e[0m'; else RED=""; GREEN=""; YELLOW=""; BOLD=""; RESET=""; fi
pass() { echo "${GREEN}PASS${RESET}  $*"; PASSED=$((PASSED + 1)); }
fail() { echo "${RED}FAIL${RESET}  $*"; FAILED=$((FAILED + 1)); }
warn() { echo "${YELLOW}WARN${RESET}  $*"; }
info() { echo "INFO  $*"; }
unknown() { echo "${YELLOW}????${RESET}  $*"; }
item() { echo "        $*"; }
section() { echo; echo "${BOLD}== $*${RESET}"; }
PASSED=0
FAILED=0

# "ok", "vulnerable" or "unknown" for an upstream version like 8.2.35 or 8.6.0RC4
classify_version() {
    local v="$1" major minor patch suffix fixed
    if [[ ! "$v" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(.*)$ ]]; then echo unknown; return; fi
    major=${BASH_REMATCH[1]}; minor=${BASH_REMATCH[2]}; patch=${BASH_REMATCH[3]}; suffix=${BASH_REMATCH[4]}
    if [ "$major" -lt 8 ] || { [ "$major" -eq 8 ] && [ "$minor" -le 1 ]; }; then
        echo vulnerable; return  # end of life upstream: only distro backports can fix these
    fi
    case "$major.$minor" in
        8.2) fixed=35 ;;
        8.3) fixed=36 ;;
        8.4) fixed=27 ;;
        8.5) fixed=12 ;;
        8.6)
            if [ -z "$suffix" ] || [ "$patch" -gt 0 ]; then echo ok; return; fi
            if [[ "$suffix" =~ ^RC([0-9]+) ]] && [ "${BASH_REMATCH[1]}" -ge 4 ]; then echo ok; else echo vulnerable; fi
            return ;;
        *) echo unknown; return ;;
    esac
    if [ "$patch" -ge "$fixed" ]; then echo ok; else echo vulnerable; fi
}

# Name of the distro package owning a file, or empty
owning_package() {
    local f="$1" pkg=""
    if command -v dpkg >/dev/null 2>&1; then
        pkg=$(dpkg -S "$f" 2>/dev/null | head -n1 | cut -d: -f1)
        # dpkg records the path it installed; follow symlinks such as /usr/bin/php -> /etc/alternatives/php
        [ -n "$pkg" ] || pkg=$(dpkg -S "$(readlink -f "$f")" 2>/dev/null | head -n1 | cut -d: -f1)
    elif command -v rpm >/dev/null 2>&1; then
        pkg=$(rpm -qf "$f" 2>/dev/null | grep -v 'not owned' | head -n1)
    elif command -v apk >/dev/null 2>&1; then
        pkg=$(apk info -W "$f" 2>/dev/null | sed -n 's/.* is owned by //p' | head -n1)
    fi
    echo "$pkg"
}

# True if the package's changelog mentions one of the CVEs (a backported fix)
changelog_has_fix() {
    local pkg="$1" doc
    if command -v dpkg >/dev/null 2>&1; then
        # PHP packages often share the changelog of phpX.Y-common
        for doc in "/usr/share/doc/$pkg" /usr/share/doc/php*-common; do
            zgrep -qE "$CVES" "$doc"/changelog.Debian.gz 2>/dev/null && return 0
        done
        return 1
    elif command -v rpm >/dev/null 2>&1; then
        rpm -q --changelog "$pkg" 2>/dev/null | grep -qE "$CVES"
    else
        return 1
    fi
}

# Reports one PHP install: where it is, its upstream version, and the owning package
report_php() {
    local where="$1" version="$2" pkg="$3"
    case "$(classify_version "$version")" in
        ok)
            pass "$where: PHP $version includes the fix" ;;
        vulnerable)
            if [ -n "$pkg" ] && changelog_has_fix "$pkg"; then
                pass "$where: PHP $version, but package $pkg lists CVE-2026-109618/109619 as fixed in its changelog (distribution backport)"
            elif [ -n "$pkg" ]; then
                fail "$where: PHP $version from package $pkg is VULNERABLE; its changelog does not mention the CVEs (update the package, then restart PHP)"
            else
                fail "$where: PHP $version is VULNERABLE (need 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or newer)"
            fi ;;
        *)
            unknown "$where: could not interpret PHP version '$version'" ;;
    esac
}

section "PHP installed on this host"
seen=""
for bin in $(command -v php php-fpm php-cgi 2>/dev/null) \
    /usr/bin/php* /usr/local/bin/php* /usr/sbin/php-fpm* /usr/local/sbin/php-fpm* /usr/lib/cgi-bin/php* \
    /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/sbin/php-fpm \
    /opt/cpanel/ea-php*/root/usr/bin/php /opt/cpanel/ea-php*/root/usr/sbin/php-fpm \
    /opt/plesk/php/*/bin/php /opt/plesk/php/*/sbin/php-fpm; do
    [ -f "$bin" ] && [ -x "$bin" ] || continue
    case "$bin" in */php-config*|*/phpize*|*/phpdbg*|*.sh) continue ;; esac  # build tools and debugger, not servers
    real=$(readlink -f "$bin" 2>/dev/null || echo "$bin")
    case " $seen " in *" $real "*) continue ;; esac
    seen="$seen $real"
    line=$("$real" -v 2>/dev/null | head -n1)
    [[ "$line" =~ ^PHP\ ([0-9][^ ]*)\ \(([a-z-]+)\) ]] || continue
    report_php "$real (${BASH_REMATCH[2]})" "${BASH_REMATCH[1]}" "$(owning_package "$real")"
done

# Apache mod_php is a library, not a binary: take the version from its package
for mod in /usr/lib/apache2/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so /usr/lib/httpd/modules/libphp*.so /etc/httpd/modules/libphp*.so; do
    [ -f "$mod" ] || continue
    real=$(readlink -f "$mod" 2>/dev/null || echo "$mod")
    case " $seen " in *" $real "*) continue ;; esac
    seen="$seen $real"
    pkg=$(owning_package "$real")
    version=""
    if [ -n "$pkg" ] && command -v dpkg-query >/dev/null 2>&1; then
        version=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null)
    elif [ -n "$pkg" ] && command -v rpm >/dev/null 2>&1; then
        version=$(rpm -q --qf '%{VERSION}' "$pkg" 2>/dev/null)
    fi
    version=$(echo "$version" | sed -E 's/^[0-9]+://; s/^([0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9]*).*/\1/')
    if [ -n "$version" ]; then
        report_php "$real (apache mod_php, highest risk)" "$version" "$pkg"
    else
        unknown "$real (apache mod_php): not from a known package; check its version with phpinfo()"
    fi
done
[ -n "$seen" ] || info "No PHP found in the standard locations on this host"

# An update replaces PHP on disk, but PHP-FPM/Apache keep running the old code
# until restarted; the kernel then shows the old binary/module as "(deleted)".
if [ -d /proc/self ]; then
    stale=""
    for p in /proc/[0-9]*; do
        exe=$(readlink "$p/exe" 2>/dev/null) || exe=""
        if [[ "$exe" == *php*" (deleted)" ]] || grep -qs 'libphp.* (deleted)' "$p/maps"; then
            stale="$stale ${p#/proc/}($(cat "$p/comm" 2>/dev/null))"
        fi
    done
    if [ -n "$stale" ]; then
        fail "Processes still running PHP code that has since been replaced on disk; restart them (e.g. systemctl restart php8.2-fpm / apache2):$stale"
    elif [ -n "$seen" ]; then
        [ "$(id -u)" -eq 0 ] && pass "No running process uses a replaced PHP binary or module" \
            || info "Run as root to also check whether running PHP processes were restarted after the update"
    fi
fi

if [ "$DOCKER" -eq 1 ]; then
    section "PHP in running Docker containers"
    if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
        unknown "Docker is not available or not accessible (run as root or a docker group member)"
    else
        found=0
        while read -r id name image; do
            [ -n "$id" ] || continue
            version=$(docker exec "$id" sh -c 'command -v php >/dev/null 2>&1 && php -r "echo PHP_VERSION;"' 2>/dev/null)
            [ -n "$version" ] || continue
            found=1
            report_php "container $name ($image)" "$version" ""
        done < <(docker ps --format '{{.ID}} {{.Names}} {{.Image}}')
        [ "$found" -eq 1 ] || info "No running container has a php binary"
        info "A fixed container image only helps once the container is rebuilt and recreated; floating tags like php:8.3 can stay cached, so pin the exact version and build with --pull"
    fi
fi

for url in $URLS; do
    section "Remote check: $url"
    powered=$(curl -s -m 15 -D - -o /dev/null "$url" | tr -d '\r' | grep -i '^x-powered-by:' | head -n1)
    if [[ "$powered" =~ PHP/([0-9][^ ]*) ]]; then
        report_php "$url" "${BASH_REMATCH[1]}" ""
        info "A remote version can't show distribution backports; if this FAILs, check the server's package changelog"
    else
        unknown "$url: no PHP version in the X-Powered-By header (expose_php is off, or not PHP); check on the server"
    fi
done

if [ "$LOGS" -eq 1 ]; then
    section "Logs since $SINCE (symptoms to review, not proof either way)"
    files=""
    for f in /var/log/nginx/*.log* /var/log/apache2/*.log* /var/log/httpd/*log* \
        /var/log/php*-fpm.log* /var/log/php-fpm/*.log* /var/log/php*/*.log* /var/log/php_errors.log* \
        /var/log/kern.log* /var/log/messages*; do
        [ -f "$f" ] && [ -r "$f" ] && files="$files $f"
    done
    tmp=$(mktemp)
    # shellcheck disable=SC2086 # word splitting of the file list is intended
    [ -z "$files" ] || for f in $files; do gzip -cdf "$f" 2>/dev/null; done > "$tmp"
    if command -v journalctl >/dev/null 2>&1; then
        journalctl --no-pager -q -o short-iso --since "$SINCE" -u 'php*' -u apache2 -u httpd -u nginx 2>/dev/null >> "$tmp"
        # kernel messages are already in kern.log/messages when those exist
        if ! ls /var/log/kern.log* /var/log/messages* >/dev/null 2>&1; then
            journalctl --no-pager -q -o short-iso --since "$SINCE" -k 2>/dev/null | grep -i 'php.*segfault' >> "$tmp"
        fi
    fi
    if [ ! -s "$tmp" ]; then
        unknown "No readable logs in /var/log or the journal (run as root; on shared hosting use your panel's log viewer)"
    else
        [ -n "$files" ] && info "Read $(echo "$files" | wc -w | tr -d ' ') log files$(command -v journalctl >/dev/null 2>&1 && echo ' plus the systemd journal')"
        # One line per finding: date<TAB>kind. Handles access logs (21/Oct/2026),
        # PHP/PHP-FPM (21-Oct-2026), nginx errors (2026/10/21), Apache errors
        # ([Wed Oct 21 ... 2026]), ISO timestamps and classic syslog (Oct 21).
        awk -v since="$SINCE" -v year="$(date +%Y)" -v oldestfile="$tmp.oldest" '
        BEGIN { n = split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m, " "); for (i = 1; i <= n; i++) mon[m[i]] = sprintf("%02d", i) }
        function day(line,   s) {
            if (match(line, /[0-9][0-9]\/[A-Z][a-z][a-z]\/[0-9][0-9][0-9][0-9]:/) || match(line, /[0-9][0-9]-[A-Z][a-z][a-z]-[0-9][0-9][0-9][0-9] /)) {
                s = substr(line, RSTART, 11); return substr(s, 8, 4) "-" mon[substr(s, 4, 3)] "-" substr(s, 1, 2)
            }
            if (match(line, /^[0-9][0-9][0-9][0-9][\/-][0-9][0-9][\/-][0-9][0-9]/)) return substr(line, 1, 4) "-" substr(line, 6, 2) "-" substr(line, 9, 2)
            if (match(line, /^\[[A-Z][a-z][a-z] [A-Z][a-z][a-z] [ 0-9][0-9] [0-9:.]* [0-9][0-9][0-9][0-9]\]/)) {
                s = substr(line, RSTART, RLENGTH); return substr(s, RLENGTH - 4, 4) "-" mon[substr(s, 6, 3)] "-" sprintf("%02d", substr(s, 10, 2) + 0)
            }
            if (match(line, /^[A-Z][a-z][a-z] [ 0-9][0-9] [0-9][0-9]:/)) return year "-" mon[substr(line, 1, 3)] "-" sprintf("%02d", substr(line, 5, 2) + 0)
            return ""
        }
        {
            kind = ""
            if ($0 ~ /Allowed memory size of [0-9]+ bytes exhausted/) kind = ($0 ~ /in Unknown on line 0/) ? "oom-startup" : "oom"
            else if ($0 ~ /exited on signal (6|7|11) |exit signal (Segmentation fault|Abort|Bus error)|php[^ ]*\[[0-9]+\]: segfault/) kind = "crash"
            else if ($0 ~ /Maximum execution time of [0-9]+ seconds? exceeded/) kind = "timeout"
            else if ($0 ~ /\] "[A-Z]+ [^"]*" [0-9][0-9][0-9] /) {
                split($0, q, "\""); split(q[3], s, " ")
                if (s[1] ~ /^50[0234]$/) kind = "http5xx"; else if (s[1] == "413") kind = "http413"; else kind = "request"
            }
            if (kind == "") next
            d = day($0)
            if (d == "") next
            if (first == "" || d < first) first = d
            if (d < since) next
            print d "\t" kind
        }
        END { print first > oldestfile }' "$tmp" | sort | uniq -c > "$tmp.counts"
        rm -f "$tmp"

        # Prints "date: count" per day for one kind
        per_day() { awk -v k="$1" '$3 == k { print "    " $2 ": " $1 }' "$tmp.counts"; }
        requests=$(awk '$3 == "request" || $3 ~ /^http/ { n += $1 } END { print n + 0 }' "$tmp.counts")
        info "$requests web requests logged since $SINCE"
        report_kind() {
            local kind="$1" text="$2" lines
            lines=$(per_day "$kind")
            if [ -n "$lines" ]; then warn "$text"; echo "$lines"; fi
        }
        report_kind oom-startup "PHP ran out of memory before any script ran ('in Unknown on line 0': usually while reading the request body). This is the condition CVE-2026-109618 needs; many of these on one day deserve a closer look:"
        report_kind crash "PHP worker crashes (segfaults / aborts). Memory-corruption exploits often crash workers while they retry:"
        report_kind oom "PHP ran out of memory inside a script (common for heavy pages, less specific):"
        report_kind timeout "PHP execution timeouts (a fatal-error path that CVE-2026-109619 can use):"
        report_kind http5xx "HTTP 500/502/503/504 responses (also caused by deploys, restarts and app bugs):"
        report_kind http413 "Requests rejected as too large (413): someone sending oversized bodies:"
        if ! awk '$3 != "request"' "$tmp.counts" | grep -q .; then
            pass "No PHP crashes, out-of-memory errors, timeouts or 5xx/413 responses in the logs since $SINCE"
        fi
        oldest=$(cat "$tmp.oldest")
        if [ -n "$oldest" ] && [[ "$oldest" > "$SINCE" ]]; then
            warn "The logs only reach back to $oldest (rotated or deleted); earlier days cannot be reviewed"
        fi
        rm -f "$tmp.counts" "$tmp.oldest"
    fi
fi

echo
if [ "$FAILED" -gt 0 ]; then
    echo "${RED}Result: $FAILED vulnerable PHP install(s) found.${RESET} Update them, restart PHP-FPM/Apache (or rebuild and recreate containers), then run this again."
    exit 1
fi
if [ "$PASSED" -eq 0 ]; then
    echo "${YELLOW}Result: no PHP install could be verified.${RESET}"
    exit 2
fi
echo "${GREEN}Result: every PHP install found includes the fix.${RESET} Remember to restart long-running PHP processes after updating."
exit 0
