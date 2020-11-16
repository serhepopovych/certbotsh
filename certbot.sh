#!/bin/sh

# Apache License 2.0
#
# Copyright (c) 2020 Serhey Popovych <serhe.popovych@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This program name
this_prog='certbot.sh'
# User to run certbot
_runas='letsencrypt'
runas="${runas:-${_runas}}"
# Group whose members able to $runas $this_prog
_certmgr='certbot'
certmgr="${certmgr:-${_certmgr}}"
# Where to install this program and symlink wrappers
install_to="/usr/local/lib/$this_prog"
symlink_dirs='/usr/local/bin /usr/local/sbin'

################################################################################

# Usage: installer ...
installer()
{
    # Requires: install(1), mktemp(1), ls(1), chmod(1), chown(1), mv(1), rm(1),
    #           ln(1), cat(1), sed(1), cmp(1),
    #           useradd(8), usermod(8), groupadd(8), id(1),
    #           certbot, lighttpd(8),
    #           systemd(timers) or crond(8), logrotate(8), killall(1) (psmisc)
    #
    # Optional: named(8) - to configure subdomain for TXT records managed by
    #                      certbot dns-rfc2136 plugin via dynamic updates
    #           patch(1) - to apply dns-rfc2136 plugin CNAME/DNAME fix from
    #                      ~${runas}/extra/bind.
    #
    # Config:  $this_prog, $runas, $certmgr, $install_to, $symlink_dirs
    # Runtime: $this, $this_dir, $prog_name

    # Usage: normalize_path() <path>
    normalize_path()
    {
        local func="${FUNCNAME:-normalize_path}"

        local path="${1:?missing 1st arg to ${func}() (<path>)}"
        local file=''

        if [ ! -d "${path}" ]; then
            file="${path##*/}"
            [ -n "$file" ] || return
            path="${path%/*}/"
            [ -d "$path" ] || return
        fi

        cd "${path}" &&
            path="${PWD%/}/${file}" &&
        cd - >/dev/null || return

        echo "${path}"
    }

    # Usage: relative_path <src> <dst>
    relative_path()
    {
        local func="${FUNCNAME:-relative_path}"

        local rp_src="${1:?missing 1st arg to ${func}() (<src>)}"
        local rp_dst="${2:?missing 2d arg to ${func}() (<dst>)}"

        # add last component from src if dst ends with '/'
        [ -n "${rp_dst##*/}" ] || rp_dst="${rp_dst}${rp_src##*/}"

        # normalize pathes first
        rp_src="$(normalize_path "${rp_src}")" || return
        rp_dst="$(normalize_path "${rp_dst}")" || return

        # strip leading and add trailing '/'
        rp_src="${rp_src#/}/"
        rp_dst="${rp_dst#/}/"

        while :; do
            [ "${rp_src%%/*}" = "${rp_dst%%/*}" ] || break

            rp_src="${rp_src#*/}" && [ -n "${rp_src}" ] || return
            rp_dst="${rp_dst#*/}" && [ -n "${rp_dst}" ] || return
        done

        # strip trailing '/'
        rp_dst="${rp_dst%/}"
        rp_src="${rp_src%/}"

        # add leading '/' for dst only: for src we will add with sed(1) ../
        rp_dst="/${rp_dst}"

        # add leading '/' to dst, replace (/[^/])+ with ../
        rp_dst="$(echo "${rp_dst%/*}" | \
                  sed -e 's|\(/[^/]\+\)|../|g')${rp_src}" || \
            return

        echo "${rp_dst}"
    }

    # Usage: rights_human2octal <rights>
    rights_human2octal()
    {
        local func="${FUNCNAME:-rights_human2octal}"

        # rwxr-xr-x (755), rwsrwSrwT (7766)
        local rights="${1:?missing 1st arg to ${func}() <rights>}"
        [ ${#rights} -eq 9 ] || return

        local val=0
        local g v s c C r

        # groups: 3  2  1  0
        # bits:  sgtrwxrwxrwx
        for g in 2 1 0; do
            v=0
            s=0

            if [ $g -ge 1 ]; then
                c='s' && C='S'
            else
                c='t' && C='T'
            fi

            r="${rights#[r-][w-][xsStT-]}"
            r="${rights%$r}"

            # [r-]
            case "$r" in
                r??)  v=$((4 + v)) ;;
                -??)  ;;
                *)    return 1 ;;
            esac

            # [w-]
            case "$r" in
                ?w?)  v=$((2 + v)) ;;
                ?-?)  ;;
                *)    return 1 ;;
            esac

            # [xsStT-]
            case "$r" in
                ??x)  v=$((1 + v)) ;;
                ??$c) v=$((1 + v)) && s=$((1 << g)) ;;
                ??$C) s=$((1 << g)) ;;
                ??-)  ;;
                *)    return 1 ;;
            esac

            val=$((val | v << (3 * g) | s << (3 * 3)))

            rights="${rights#$r}"
        done

        printf '%04o\n' "$val"
    }

    # Usage: file_rights_human <file>
    file_rights_human()
    {
        local func="${FUNCNAME:-file_rights_human}"

        local file="${1:?missing 1st arg to ${func}() <file>}"

        [ -e "$file" ] || return

        set -- $(ls -l "$file") || return

        local rights="$1"
        rights="${rights#?}"
        [ ${#rights} -eq 9 ] || rights="${rights%?}"

        case "$rights" in
           [r-][w-][xsS-][r-][w-][xsS-][r-][w-][xtT-]) ;;
           *) return 1 ;;
        esac

        echo "$rights"
    }

    # Usage: file_rights_octal <file>
    file_rights_octal()
    {
        local func="${FUNCNAME:-file_rights_octal}"

        local file="${1:?missing 1st arg to ${func}() <file>}"

        local rights

        rights="$(file_rights_human "$file")" || return
        rights_human2octal "$rights"
    }

    # Usage: file_owner_human <file>
    file_owner_human()
    {
        local func="${FUNCNAME:-file_owner_human}"

        local file="${1:?missing 1st arg to ${func}() <file>}"

        [ -e "$file" ] || return

        set -- $(ls -l "$file") || return

        [ -n "$3" -a -n "$4" ] || return

        echo "$3:$4"
    }

    # Usage: file_owner_octal <file>
    file_owner_octal()
    {
        local func="${FUNCNAME:-file_owner_octal}"

        local file="${1:?missing 1st arg to ${func}() <file>}"

        local owner uid gid

        owner="$(file_owner_human "$file")" || return

        uid="$(id -u "${owner%:*}")" || return
        gid="$(id -g "${owner#*:}")" || return

        echo "$uid:$gid"
    }

    # Usage: new <target> [<owner>] [<group>] [<mode>]
    new()
    {
        local func="${FUNCNAME:-new}"

        local target="${1:?missing 1st arg to ${func}()}"
        local owner="${2:-$runas}"
        local group="${3:-root}"
        local mode="${4-}"

        if [ -e "$target" ]; then
            # Directory or non-directory?
            if [ -n "${target%%*/}" ]; then
                [ -f "$target" ] || return
            else
                [ -d "$target" ] || return
            fi

            # Update ownership
            chown "$owner:$group" "$target" || return
            # Update permissions
            [ -z "$mode" ] || chmod "$mode" "$target" || return
        else
            # Catch recursive call, if any
            [ -z "${in_new-}" ] || return
            local in_new=1

            # There might be broken symlink
            rm -f "$target" ||:

            # Directory or regular file?
            if [ -n "${target%%*/}" ]; then
                :>"$target" && new "$@" || return
            else
                install -d ${mode:+-m $mode} \
                    -o "$owner" -g "$group" "$target" || return
            fi
        fi
    }

    # Usage: put <out>
    put()
    {
        local func="${FUNCNAME:-put}"

        local out="${1:?missing 1st arg to ${func}() (<out>)}"
        local t m o rc=0

        t="$(mktemp "$out.XXXXXXXX")" || return

        if cat >"$t"; then
            if cmp -s "$t" "$out"; then
                :
            else
                if [ -e "$out" ]; then
                    m="$(file_rights_octal "$out")" &&
                    chmod "$m" "$t" || rc=$?
                    o="$(file_owner_human "$out")" &&
                    chown "$o" "$t" || rc=$?
                fi
                while [ $rc -eq 0 ]; do
                    if [ -L "$out" ] || [ -e "$out" -a ! -f "$out" ]; then
                        rm -f "$out" ||:
                    fi
                    if [ -e "$out" ]; then
                        [ -z "${put__skip_existing-}" ] || break
                        out="$out.certbotsh-new"
                    fi
                    mv -f "$t" "$out" || rc=$?
                    break
                done
            fi
        else
            rc=$?
        fi

        [ ! -e "$t" ] || rm -f "$t" || rc=$((rc + $?))

        return $rc
    }

    # Usage: server_http_conf [<hostname>] [<domain>]
    server_http_conf()
    {
        local d="${2:-example.com}"
        local h="${1:-acme-le.gw.api.$d}"

        local log_root='/var/log/lighttpd'
        local server_root='/var/www'
        local conf_dir='/etc/lighttpd'

        local lighttpd_group='www-data'
        if ! id -g "$lighttpd_group" >/dev/null 2>&1; then
            lighttpd_group='lighttpd'
            if ! id -g "$lighttpd_group" >/dev/null 2>&1; then
                groupadd \
                    -r -f \
                    "$lighttpd_group" \
                    #
            fi
        fi # lighttpd_group
        local lighttpd_user='www-data'
        if ! id -u "$lighttpd_user" >/dev/null 2>&1; then
            lighttpd_user='lighttpd'
            if ! id -u "$lighttpd_user" >/dev/null 2>&1; then
                useradd \
                    -r \
                    -g "$lighttpd_group" \
                    -c 'lighttpd web server' \
                    -d "$server_root" \
                    -s '/bin/false' \
                    "$lighttpd_user" \
                    #
            fi
        fi # lighttpd_user

        local s t

        t="$conf_dir/" && new "$t" 'root' 'root'
        t="${t}lighttpd.conf"

        if [ -f "$t" ]; then
            s="$t.certbotsh-orig"
            [ -f "$s" ] || mv -f "$t" "$s"
        fi

        put "$t" <<EOF

## Requires lighttpd 1.4.54+

##### Load required server modules #####

server.modules += (
    "mod_accesslog",
    "mod_openssl",
    "mod_access",
#    "mod_auth",
#    "mod_authn_file",
    "mod_evasive",
    "mod_setenv",
    "mod_userdir",
    "mod_redirect",
    "mod_rewrite",
)

##### Variable definition which will make configuration easier #####

# Common variables
var.log_root    = "$log_root"
var.server_root = "$server_root"
var.state_dir   = "/var/run"
var.conf_dir    = "$conf_dir"

# Base directory with authentication data
var.auth_dir    = conf_dir + "/auth"

# Base directory with certs and keys
var.pki_dir     = conf_dir + "/pki"

# Base directory for all vhosts configuration
var.vhosts_d    = conf_dir + "/vhosts.d"

##### General server settings #####

# Suppress lighty version from "Server" field in the http headers.
server.tag = "lighttpd"

# Perform initial configuration steps (e.g. open socket
# on privileged port 80, write pid file, change process
# limit on file descriptions, etc.) and drop privileges.
server.username = "$lighttpd_user"
server.groupname = "$lighttpd_group"

# Error logging.
server.errorlog = log_root + "/error.log"

##### Network settings and performance tuning #####

# Explicitly open non-SSL sockets for each address family
server.bind = ""
server.port = 0

# Listen on IPv4 and/or IPv6 socket(s).
\$SERVER["socket"] == "0.0.0.0:80" { }
\$SERVER["socket"] == "[::]:80" { }

# Use high-performance file descriptor event pooling on Linux.
server.event-handler = "linux-sysepoll"

# Use sendfile(2) as backend for sending files.
server.network-backend = "sendfile"

# Increase limit on file descriptors.
server.max-fds = 2048

# Maximum number of connections supported by the server (max-fds / 3).
server.max-connections = 640

# Cache stat(2) syscalls.
server.stat-cache-engine = "simple"

# Tune up socket IO timeouts.
server.max-read-idle = 30
server.max-write-idle = 180

# How many seconds to keep a keep-alive connection open, until we consider it idle.
server.max-keep-alive-idle = 5

# How many keep-alive requests until closing the connection.
server.max-keep-alive-requests = 16

##### Filesystem configurations #####

# Set document root, upload directory etc.
server.document-root = server_root + "/empty"
server.upload-dirs = ( "/var/tmp" )

## Store process id in this file.
#server.pid-file = state_dir + "/lighttpd.pid"

# Do not follow symlinks by default.
server.follow-symlink = "disable"

# Sane index file names by default: each vhost will configure it's own.
index-file.names = ( "index.html" )

# Deny access the file-extensions.
url.access-deny = ( "~", ".bak", ".inc" )

# Directory listing configuration.
dir-listing.activate = "disable"

# mimetype mapping.
mimetype.assign += (
    ".html" => "text/html",
    "" => "application/octet-stream"
)

##### Access logging options #####

# Access log configuration.
accesslog.filename = log_root + "/access.log"

##### SSL configuration #####

# Enable globally
ssl.engine      = "enable"
ssl.cipher-list = "TLSv1.2:!aNULL:!eNULL:!LOW:!MEDIUM:!EXP:!kRSA:!AES256"

# It is expected that global certificate is a wildcard
# including second and above subdomains as subjectAltName (SAN)
ssl.pemfile = pki_dir + "/wildcard/" + "cert.pem"
ssl.privkey = pki_dir + "/wildcard/" + "privkey.pem" # 1.4.53+
ssl.ca-file = pki_dir + "/wildcard/" + "chain.pem"
#ssl.dh-file = pki_dir + "/dh2048.pem"

# Inherit global settings (not only SSL) in 1.4.46+
# https://redmine.lighttpd.net/projects/lighttpd/wiki/Docs_SSL
\$SERVER["socket"] == "0.0.0.0:443" { ssl.engine = "enable" }
\$SERVER["socket"] == "[::]:443"    { ssl.engine = "enable" }

##### Virtual hosts #####

# Include vhosts configuration.
include vhosts_d + "/*/conf"
EOF
        new "$t" 'root' 'root' 0644

        # $conf_dir/auth
        new "$conf_dir/auth/" 'root' 'root'

        # $conf_dir/pki
        t="$conf_dir/pki/" && new "$t" 'root' 'root'
        cd "$t" &&
            ln -sf "../../letsencrypt/live/$h" &&
            ln -sf "../../letsencrypt/live/$d" &&
            ln -sf "$d" 'wildcard' &&
        cd - >/dev/null

        # $conf_dir/vhosts.d/$h
        s="$conf_dir/vhosts.d/$h"
        new "$s/auth/"   'root' 'root'
        new "$s/conf.d/" 'root' 'root'

        # $conf_dir/vhosts.d/$h/pki
        ln -sf "../../pki/$h" "$s/pki"

        # $conf_dir/vhosts.d/$h/users.d
        t="$s/users.d/" && new "$t" 'root' 'root'

        # $conf_dir/vhosts.d/$h/xbin/users-conf.sh
        t="$s/xbin/" && new "$t" 'root' 'root'

        # $conf_dir/vhosts.d/$h/conf
        t="$s/conf" && put "$t" <<EOF

\$HTTP["host"] =~ "^$(echo "$h" | sed -e 's/\./\\./g')(:|\$)" {
  var.server_name = "$h"

  ## common filesystem paths

  var.vhosts_d = vhosts_d + "/" + server_name

  var.auth_dir = vhosts_d + "/auth"
  var.pki_dir  = vhosts_d + "/pki"
  var.xbin_dir = vhosts_d + "/xbin"

  var.log_root = log_root + "/" + server_name

  ## userdir

  var.userdir_include_users = (
    "${runas}"
  )

  var.userdir_path = "${htdocsdir##*/}"


  # Common server configuration
  server.name = server_name

  # Must be empty, read-only directory
  server.document-root = server_root + "/empty"

  # Forbid all http methods except GET
  \$HTTP["request-method"] !~ "^GET\$" {
    url.access-deny = ( "" )
  }

  # User home subdirectory
  userdir.path = userdir_path
  userdir.include-user = userdir_include_users

  # Access logging
  accesslog.filename = log_root + "/access.log"

  \$HTTP["scheme"] == "http" {
    # Tune up socket IO timeouts
    server.max-read-idle = 30
    server.max-write-idle = 60

    # Disable keep-alive functionality
    server.max-keep-alive-requests = 0

    url.redirect-code = 301
    # This requires 1.4.50+ as we do not have access to %n from \$HTTP["host"] here
    url.redirect = ( "" => "https://\${url.authority}\${url.path}\${qsa}" )
  }

  \$HTTP["scheme"] == "https" {
    # SSL
    ssl.pemfile = pki_dir + "/cert.pem"
    ssl.privkey = pki_dir + "/privkey.pem" # 1.4.53+
    ssl.ca-file = pki_dir + "/chain.pem"

    # HSTS
    setenv.add-response-header += (
      "Strict-Transport-Security" => "max-age=31536000; includeSubdomains"
    )

    # Follow symlinks
    server.follow-symlink = "enable"

    # Make PKCS#12 accessible only from remote IPs of host they issued to
    $HTTP["remoteip"] =~ ".+" {
      url.rewrite-once = (
          "^/(~[^/]+)((/[^/]+)*)/(([^/]+)\.p12)$" => "/$1/$5/%0$2/$4",
          "" => "/"
      )
    }

    # Per IP connection limit
    evasive.max-conns-per-ip = 10
    evasive.silent = "disable"

#    # Authentication
#    auth.backend = "htdigest"
#    auth.backend.htdigest.userfile = auth_dir + "/users.htdigest"
#
#    auth.require = ( "" =>
#                     (
#                       "method"  => "digest",
#                       "realm"   => "Restricted area",
#                       "require" => "user=${runas}"
#                     )
#                   )
  }
}
EOF
        new "$t" 'root' 'root' 0644

        # $server_root/empty
        t="$server_root/empty/" && new "$t" 'root' 'root' 0755
        t="${t}index.html"       && put "$t" <<'_EOF'
_EOF
        new "$t" 'root' 'root' 0644

        # $log_root/$h
        t="$log_root/"    && new "$t" "$lighttpd_user" "$lighttpd_group" 0750
        s="$log_root/$h/" && new "$s" "$lighttpd_user" "$lighttpd_group" 0750

        # /etc/logrotate.d/lighttpd.$h
        t='/etc/logrotate.d/' && new "$t" 'root' 'root'
        t="${t}lighttpd.$h" && put "$t" <<EOF
${s}*log {
    missingok
    notifempty
    sharedscripts
    su ${lighttpd_user} ${lighttpd_group}
    postrotate
        /usr/bin/killall -HUP lighttpd >/dev/null 2>&1 || :
    endscript
}
EOF
        new "$t" 'root' 'root' 0644
    } # server_http_conf

    # Usage: server_cron_conf ...
    server_cron_conf()
    {
        local s t

        # Provide crontab entries for certificate renewal that bail out
        # on systemd(1) targets that assumed to use systemd.timer(5) and
        # executed on non systemd(1) targets.
        t='/etc/cron.d/' && new "$t" 'root' 'root'
        t="${t}certbot"  && put "$t" <<EOF
# $t: crontab entries for the certbot package
#
# Upstream recommends attempting renewal twice a day
#
# Eventually, this will be an opportunity to validate certificates
# haven't been revoked, etc.  Renewal will only occur if expiration
# is within 30 days.
SHELL=/bin/sh
PATH=/sbin:/bin:/usr/sbin:/usr/bin
0 */12 * * * ${runas} test \! -d /run/systemd/system && sleep \$((\$$ \% 43200)) && certbot -q renew
EOF
        new "$t" 'root' 'root' 0644

        # Tweak systemd.service unit to $runas and enable timer
        for s in \
            'certbot.service' \
            'certbot-renew.service' \
            #
        do
            t="/lib/systemd/system/$s"
            [ -f "$t" ] || continue

            sed -e "/^Type=oneshot\$/aUser=${runas}\\
Group=${runas}" "$t" >"/etc/systemd/system/$s"

            t="${s%.service}.timer"
            systemctl enable --now "$t"

            break
        done
    } # server_cron_conf

    # Usage: server_log_conf ...
    server_log_conf()
    {
        local s t

        # Configure logging
        s='/var/log/letsencrypt/' && new "$s"

        # Config logrotate
        t='/etc/logrotate.d/' && new "$t" 'root' 'root'
        t="${t}certbot"       && put "$t" <<EOF
${s}*.log {
    rotate 12
    weekly
    su ${runas} ${runas}
    compress
    missingok
}
EOF
        new "$t" 'root' 'root' 0644
    } # server_log_conf

    # Usage: server_extra_conf ...
    server_extra_conf()
    {
        [ -d "$extradir" ] || return
        local s t

        # bind
        s="$extradir/bind/"

        t="$s" && new "$t" "$runas" "$runas" 0755

        # named.acme-le.zones
        t="${s}named._acme-le.zones" && put "$t" <<'_EOF'
zone "_acme-le.example.com" IN {
	type master;
	file "named._acme-le.example.com";
	update-policy {
		grant acme-le.gw.api.example.com-key wildcard *._acme-le.example.com. txt;
	};
};
_EOF
        new "$t" "$runas" "$runas" 0644

        # named._acme-le.example.com
        t="${s}named._acme-le.example.com" && put "$t" <<'_EOF'
$TTL 21600	; 6 hours
@	IN SOA	ns hostmaster.example.com. (
			2020031256 ; serial
			21600      ; refresh (6 hours)
			3600       ; retry (1 hour)
			1209600    ; expire (2 weeks)
			3600       ; minimum (1 hour)
			)
	IN NS	ns
	IN A	127.0.1.1
ns	IN A	127.0.1.1
_EOF
        new "$t" "$runas" "$runas" 0644

        # README
        t="${s}README" && put "$t" <<'_EOF'
This example BIND9 configuration and zone files for Dynamic DNS updates
as per rfc2136 that will be used with certbot dns-rfc2136 plugin.

Steps necessary to configure BIND may vary from distro to distro, however
they can be summarized to following:

    1) copy named._acme-le.zones file to /etc/
    2) add following directive to
           include "/etc/named._acme-le.zones";
       to /etc/named.local.zones
    3) copy named._acme-le.example.com to /var/named;
       make sure user running named(8) service can write to that file
       and directory containing it for Dynamic DNS updates support
    4) generate TSIG key to control
         tsig-keygen >>/etc/named.tsig.key \
             -a hmac-sha256 acme-le.gw.api.example.com-key
       (make sure /etc/named.tsig.key included from named.conf
        or other file included from named.conf)
    5) adjust values (espeically serial) in named._acme-le.example.com
       and restart named(8) service (e.g. service named restart); check
       its status
    6) delegate subdomain _acme-le.example.com from example.com;
       this can be either done by configuring example.com zone file
       or using hosting provider control panel.

For security reasons it is not recommended to run bind service to
perform dns-01 authentications on same host where certbot is running
(i.e. acme-le.gw.api.example.com): in case of any flaws in publicly
available network service that host might be compromised giving access
to certificate management communication channel.

For same reason firewall must be configured on certbot host to restrict
access to other services (e.g. http/ssh server).

Instead dedicated server/container should be provisioned for that purpose.
_EOF
        new "$t" "$runas" "$runas" 0644

        # certbot
        s="$extradir/certbot/"

        t="$s" && new "$t" "$runas" "$runas" 0755

        # dns-rfc2136 plugin patch (rebased for version 1.0.0 in EPEL7)
        local n='dns-rfc2136-cname-and-dname.patch'

        t="${s}${n}" && put "$t" <<'_EOF'
From 3774046bd5fc58a6fb29fcfcdefbf66dc4cb517a Mon Sep 17 00:00:00 2001
From: "H. Peter Anvin" <hpa@zytor.com>
Date: Thu, 21 Feb 2019 12:36:26 -0800
Subject: [PATCH] dns-rfc2136: find the correct zone/name when CNAME/DNAMEs are
 used

Dynamic zones have significant problems with DNSSEC and with redundant
servers (which, of course is highly desirable for DNS.) The obvious
solution to that is to use a CNAME or DNAME record to point the
_acme-challenge to a different zone which can have different NS and
TTL properties. In particular, breaking DNSSEC support breaks exactly
the chain of trust on which ACME depends, and is thus extremely
undesirable.

In order to find the correct base zone and name-in-zone when
CNAME/DNAMEs might be present, search from the top down instead of the
bottom up, and allow non-authoritative answers for anything other than
the final SOA. There is no guarantee that the authentication server is
authoritative for anything but the zone into which the TXT record is
to be placed.

If the authentication server disallows recursion, this code will this
do the right thing as long as the server is authoritative for the
dynamic zone and any zone which contains a CNAME or DNAME record. If
that is not the case, then the server must support recursion for its
dynamic clients; it obviously does not need to offer that service to
the general public. If even this turns out to be unacceptable, then
the solution would be to query the normal nameservers (using the
system resolver), at least if an !AA !RA response is returned. The
dns.resolver module has a zone_for_name() function, but unfortunately
it does not return the name-in-zone, and to me its algorithm appears
to be incorrect (at least for our purposes) in a way that is similar
to the previous dns-rfc2136 code.

This patch changes several levels of the interface to use
dns.name.Name objects instead of strings, and passes dns.rdata.Rdata
objects between _query_soa() and _find_domain(). This turns out to
significantly simplify a fair number of things, but requires a fair
number of changes to the test suite. Clean up the test suite by
implementing a mock resolver with a mapping instead of a simple
sequence of return values, and by precomputing dns.name.Name objects
for (sub)domains and prefixes used.

Signed-off-by: H. Peter Anvin <hpa@zytor.com>
---
https://bugzilla.redhat.com/show_bug.cgi?id=1679796
https://github.com/certbot/certbot/pull/7244

diff -urN a/dns_rfc2136.py b/dns_rfc2136.py
--- a/dns_rfc2136.py
+++ b/dns_rfc2136.py
@@ -15,6 +15,7 @@
 from certbot import errors
 from certbot import interfaces
 from certbot.plugins import dns_common
+from collections import defaultdict
 
 logger = logging.getLogger(__name__)
 
@@ -109,11 +110,9 @@
         :raises certbot.errors.PluginError: if an error occurs communicating with the DNS server
         """
 
-        domain = self._find_domain(record_name)
+        logger.debug('Adding TXT record: %s %d "%s"', record_name, record_ttl, record_content)
 
-        n = dns.name.from_text(record_name)
-        o = dns.name.from_text(domain)
-        rel = n.relativize(o)
+        (rel, domain) = self._find_domain(record_name)
 
         update = dns.update.Update(
             domain,
@@ -144,11 +143,7 @@
         :raises certbot.errors.PluginError: if an error occurs communicating with the DNS server
         """
 
-        domain = self._find_domain(record_name)
-
-        n = dns.name.from_text(record_name)
-        o = dns.name.from_text(domain)
-        rel = n.relativize(o)
+        (rel, domain) = self._find_domain(record_name)
 
         update = dns.update.Update(
             domain,
@@ -174,53 +169,156 @@
         Find the closest domain with an SOA record for a given domain name.
 
         :param str record_name: The record name for which to find the closest SOA record.
-        :returns: The domain, if found.
-        :rtype: str
-        :raises certbot.errors.PluginError: if no SOA record can be found.
+        :returns: tuple of (`entry`, `zone`) where
+                `entry` - canonical relative entry into the target zone;
+                `zone` - canonical absolute name of the zone to be modified.
+        :rtype: (`dns.name.Name`, `dns.name.Name`)
+        :raises certbot.errors.PluginError: if the search failed for any reason.
         """
 
-        domain_name_guesses = dns_common.base_domain_name_guesses(record_name)
-
-        # Loop through until we find an authoritative SOA record
-        for guess in domain_name_guesses:
-            if self._query_soa(guess):
-                return guess
+        # Note: an absolute dns.name.Name ends in dns.name.root, which
+        # is non-empty. Therefore the first prefix.split(1) splits off
+        # dns.name.root, i.e. example.com. -> (example.com, .), not
+        # example.com. -> (example, com.).  dns.name.empty, however,
+        # is an actual empty name, has a truth value of False, and is
+        # an identity element for the append operation; thus
+        # dns.name.root + dns.name.empty == dns.name.root.
+        #
+        # This code relies on these properties.
+
+        domain = dns.name.from_text(record_name)
+        prefix = domain
+        suffix = dns.name.empty
+        found  = None
+        domstr = str(domain)    # For messages, may have a DNAME/CNAME added
+
+        # The domains already queried and the corresponding results
+        domain_names_searched = dict()
+
+        while prefix:
+            (prefix, next_label) = prefix.split(1)
+            suffix = next_label + suffix
+
+            # Don't re-query if we have already been here (normal
+            # during DNAME/CNAME re-walk)
+            if suffix in domain_names_searched:
+                result = domain_names_searched[suffix]
+            else:
+                result = self._query_soa(suffix)
+                domain_names_searched[suffix] = result
+
+            (auth, rr) = result
+            if rr is None:
+                # Nothing to do, just descend the DNS hierarchy
+                pass
+            elif rr.rdtype == dns.rdatatype.SOA:
+                # We found an SOA, authoritative or not
+                found = (auth, prefix, suffix)
+            else:
+                # We found a DNAME or CNAME. We need to start the walk over
+                # from the common point of departure.
+                target = rr.target
+                if target in domain_names_searched:
+                    # DNAME/CNAME loop!
+                    raise errors.PluginError('%s %s loops seeking SOA for %s',
+                                             suffix, repr(rr), domstr)
+
+                # Restart from the root, replacing the current suffix
+                prefix = prefix + target
+                suffix = dns.name.empty
+                found  = None
+                domstr = str(domain)+' ('+str(prefix)+')' # For messages
+
+        if not found:
+            raise errors.PluginError('No SOA of any kind found for %s',
+                                     domstr)
+
+        (auth, prefix, suffix) = found
+        if not auth:
+            raise errors.PluginError('SOA %s for %s not authoritative',
+                                     suffix, domstr)
+        return (prefix, suffix)
 
-        raise errors.PluginError('Unable to determine base domain for {0} using names: {1}.'
-                                 .format(record_name, domain_name_guesses))
-
-    def _query_soa(self, domain_name):
+    def _query_soa(self, domain):
         """
         Query a domain name for an authoritative SOA record.
 
-        :param str domain_name: The domain name to query for an SOA record.
-        :returns: True if found, False otherwise.
-        :rtype: bool
+        :param dns.name.Name domain: The domain name to query for an SOA record.
+        :returns: (`authoritative`, `rdata`) if found
+                autoritative bool if response was authoritative
+                rdata dns.rdata.Rdata or None the returned record
+        :rtype: (`bool`, `dns.rdata.Rdata` or `None`)
         :raises certbot.errors.PluginError: if no response is received.
         """
 
-        domain = dns.name.from_text(domain_name)
+        # In order to capture any possible CNAMEs, we have to do the
+        # search upward from the root. On the way, any time we find a
+        # SOA record, save it; the final SOA record captured is the
+        # target. If that SOA record is not authoritative, then
+        # we have a fatal error.
+        #
+        # As we want to know about either type, we request recursion
+        # from the target name server. If the target nameserver does
+        # not provide recursion services, it will still work for
+        # finding an authoritative SOA, DNAME or CNAME record
+        # in a zone for which the nameserver is authoritarive; this is
+        # expected to be the common case, although it is not 100%
+        # guaranteed. The only ways to avoid that, ultimately, is to use
+        # a trusted recursive nameserver instead if we get a !RA response
+        # (e.g. using dns.resolver?) or actually query the authoritative name
+        # servers all the way from the top.
+        #
+        # We intentionally only look in the answer section, not in
+        # the authority or additional sections, and only for records
+        # which match the requested domain name exactly.
+        #
+        # If we get more than one SOA, DNAME, or CNAME record of the
+        # same type and exactly matching the requested domain in the
+        # *answer* section we are really in an error situation (these
+        # are all singleton RRs), but try to make the best of the
+        # situation.
 
         request = dns.message.make_query(domain, dns.rdatatype.SOA, dns.rdataclass.IN)
-        # Turn off Recursion Desired bit in query
-        request.flags ^= dns.flags.RD
 
         try:
+            logmsg = 'Query '+str(domain)
             try:
                 response = dns.query.tcp(request, self.server, port=self.port)
             except OSError as e:
                 logger.debug('TCP query failed, fallback to UDP: %s', e)
                 response = dns.query.udp(request, self.server, port=self.port)
             rcode = response.rcode()
+            logmsg += ': '+dns.rcode.to_text(rcode)
 
-            # Authoritative Answer bit should be set
-            if (rcode == dns.rcode.NOERROR and response.get_rrset(response.answer,
-                domain, dns.rdataclass.IN, dns.rdatatype.SOA) and response.flags & dns.flags.AA):
-                logger.debug('Received authoritative SOA response for %s', domain_name)
-                return True
-
-            logger.debug('No authoritative SOA record found for %s', domain_name)
-            return False
+            auth = (response.flags & dns.flags.AA) != 0
+            if auth:
+                logmsg += ', authoritative'
+            else:
+                logmsg += ', non-authoritative'
+
+            found = dict()
+            for rrset in response.answer:
+                if rrset.name != domain: continue
+                if rrset.rdclass != dns.rdataclass.IN: continue
+                for rr in rrset:
+                    if not rr.rdtype in found:
+                        found[rr.rdtype] = [rr]
+                    elif not rr in found[rr.rdtype]:
+                        # Explicitly ignore exact duplicate RRs
+                        found[rr.rdtype].append(rr)
+
+            for rdtype in found:
+                logmsg += ' %s %d' % (dns.rdatatype.to_text(rdtype), len(found[rdtype]))
+
+            retrr = None
+            for rdtype in dns.rdatatype.SOA, dns.rdatatype.DNAME, dns.rdatatype.CNAME:
+                if rdtype in found:
+                    retrr = found[rdtype][0]    # Use the first one returned
+                    break
+
+            logmsg += ', returning '+repr(retrr)
+            logger.debug(logmsg)
+            return (auth, retrr)
         except Exception as e:
             raise errors.PluginError('Encountered error when making query: {0}'
                                      .format(e))
_EOF
        # """ patch makes crazy syntax highlighing in some editors
        new "$t" "$runas" "$runas" 0644

        # README
        t="${s}README" && put "$t" <<EOF
Currently certbot dns-rfc2136 plugin does not support CNAME and/or DNAME lookups
to find target zone for TXT record needed by dns-01 validation.

There are number of attempts to bring CNAME/DNAME support neigher of which
accepted to upstream as per Jul 2020. One most clean and simple made by RedHat
as part of https://bugzilla.redhat.com/show_bug.cgi?id=1679796. However that one
not part of EPEL and patch must be applied explicitly on RHEL/CentOS systems as
well as on non-RHEL systems with following commands:

    # Support both certbot 1.4.0 (python2) and 1.5.0+ (python3) on
    # RHEL/CentOS 7.x and 8.x. On non-RHEL systems pathes may vary.
    # Run certbot as root to make sure it recompiles .pyo/.pyc files.

    $ if cd /usr/lib/python2.7/site-packages/certbot_dns_rfc2136/_internal ||
         cd /usr/lib/python3.6/site-packages/certbot_dns_rfc2136/_internal
      then
          sudo patch <${s}${n}
          cd - >/dev/null
      fi
    $ sudo /usr/bin/certbot -h all

Follow RedHat bugzilla entry and upstream github.com pull/issue discussions for
more details:

    https://bugzilla.redhat.com/show_bug.cgi?id=1679796
    https://github.com/certbot/certbot/pull/7244
EOF
        new "$t" "$runas" "$runas" 0644
    } # server_extra_conf

    # Usage: cli_ini ...
    cli_ini()
    {
        [ -d "$configdir" ] || return
        local t="$configdir/cli.ini"

        # cli.ini
        put "$t" <<EOF
# See https://certbot.eff.org/docs/using.html#configuration-file for more details.

# This is an example of the kind of things you can do in a configuration file.
# All flags used by the client can be configured here. Run Certbot with
# "--help" to learn more about the available options.
#
# Note that these options apply automatically to all use of Certbot for
# obtaining or renewing certificates, so options specific to a single
# certificate on a system with several certificates should not be placed
# here.

# Disable internal certbot logrotation since logrotate(8) is used.
max-log-backups=0

# Agree to the ACME server's Subscriber Agreement.
agree-tos

# Don't share your e-mail address with EFF.
no-eff-email

# A sorted, comma delimited list of the preferred
# challenge to use during authorization
preferred-challenges = dns

# Use a 4096 bit RSA key instead of default (2048)
#rsa-key-size = 4096

# When renewing, use the same private key as the existing certificate.
reuse-key

# Uncomment and update to register with the specified e-mail address
#email = foo@example.com

# Deploy hook called after successfuly obtained/renewed certificate.
deploy-hook = $homedir/bin/certbotsh-publish

# Uncomment to use the dns-rfc2136 authenticator. Provide dynamic zone
# updates credentials in separate configuration file (e.g. rfc2136.ini).
authenticator = dns-rfc2136
dns-rfc2136-credentials = $configdir/rfc2136.ini
dns-rfc2136-propagation-seconds = 10
EOF
        new "$t" "$runas" "$runas" 0400
    } # cli_ini

    # Usage: rfc2136_ini ...
    rfc2136_ini()
    {
        [ -d "$configdir" ] || return
        local t="$configdir/rfc2136.ini"

        # rfc2136.ini
        put "$t" <<'_EOF'
# See https://certbot-dns-rfc2136.readthedocs.io/en/stable/ for more details.

# Target DNS server
dns_rfc2136_server = 127.0.0.1
# Target DNS port
dns_rfc2136_port = 53
# TSIG key name
dns_rfc2136_name = keyname.
# TSIG key secret
dns_rfc2136_secret = <secret>
# TSIG key algorithm
dns_rfc2136_algorithm = HMAC-SHA256
_EOF
        new "$t" "$runas" "$runas" 0400
    } # rfc2136_ini

    # Usage: publish_cfg ...
    publish_cfg()
    {
        [ -d "$configdir" ] || return
        local t="$configdir/publish.cfg"

        # publish.cfg
        put "$t" <<EOF
# Directory where to deploy new/renewed certificate lineages
#pubdir="$htdocsdir"

# Options to pwgen(1)
#pwgen_opts='-ncysB1 16'

# Options to openssl pkcs12(1)
#pkcs12_opts='-keypbe aes-256-cbc -certpbe aes-256-cbc -macalg sha256'
EOF
        new "$t" "$runas" "$runas" 0400
    } # publish_cfg

    # Usage: update_cfg ...
    update_cfg()
    {
        [ -d "$configdir" ] || return
        local t="$configdir/update.cfg"

        # update.cfg
        put "$t" <<EOF
# List of certificates to update. Order affects pre/post hooks execution order.
#certs='ftp www wildcard'

# Hooks executed as /bin/sh -c "<hook>" {'pre_hook'|'deploy_hook'|'post_hook'}.
# Therefore any valid shell statement is supported as part of hook. This can
# be used to stack multiple commands in single hook by separating them with ";"
# like shown in this example or use any other shell statement.
#
# Hooks can use 'cookie' variable (and only that one recognized to prevent code
# injection) to communicate (pass data between invocations) with each other. For
# instance pre hook implemented by certbotsh-hook can set running_<service>=1 in
# cookie if service was running and stopped successfuly, that post hook will
# inspect and start service.
#
# In this particular example it is assumed that all certificates updated at same
# time so that post hook of wildcard certificate triggers lighttpd stop/start.
# If not uncomment post hook for each individual certificate.
#
# Note that first occurence of comment in multi command hook will implicitly
# comment all lines that follow it. Thus it is suggested to comment only last
# line.

# ftp
ftp_url='https://acme-le.gw.api.example.com/~letsencrypt'
ftp_domain='ftp.example.com'
ftp_ph='<passphrase_ftp>'
ftp_deploy_hook='
    runas=root certbotsh-hook deploy lighttpd;
    runas=root certbotsh-hook deploy vsftpd@ftp.example.com;
'
ftp_post_hook='
    runas=root certbotsh-hook post vsftpd@ftp.example.com;
    #runas=root certbotsh-hook post lighttpd;
'

# www
www_url='https://acme-le.gw.api.example.com/~letsencrypt'
www_domain='www.example.com'
www_ph='<passphrase_www>'
www_deploy_hook='runas=root certbotsh-hook deploy lighttpd'
#www_post_hook='runas=root certbotsh-hook post lighttpd'

# wildcard
wildcard_url='https://acme-le.gw.api.example.com/~letsencrypt'
wildcard_domain='example.com'
wildcard_ph='<passphrase_wildcard>'
wildcard_deploy_hook='runas=root certbotsh-hook deploy lighttpd'
wildcard_post_hook='runas=root certbotsh-hook post lighttpd'
EOF
        new "$t" "$runas" "$runas" 0400
    } # update_cfg

    local put__skip_existing=''
    local homedir configdir cachedir extradir htdocsdir
    local t r
    local sudoers_line_runas sudoers_line_root sudoers_progs

    # Usage: usage ...
    usage()
    {
        local rc=$?
        cat >&2 <<EOF
usage: [vars] $prog_name {install [client|server|all] | update}

If argument to install is not specified 'client' is assumed.

Accepted environment variables (e.g. in [vars]) with their defaults are

    runas=${_runas}
                      User to install (and run) services as
    certmgr=${_certmgr}
                      Group whose members allowed to run services

    httpd_domain=example.com
                      Domain used for default (wildcard) server
    httpd_hostname=acme-le.gw.api.\$httpd_domain
                      Virtual host name to configure in httpd

Report bugs to http://github.com/serhepopovych/certbotsh
EOF
        echo >&2
        exit $rc
    }

    if [ ! -f "$this" ]; then
        echo >&2 "$prog_name: \"$this\" is not found (read from stdin or -c?)"
        exit 1
    fi

    if [ x$(id -u) != x0 ]; then
        echo >&2 "$prog_name: must run as uid 0"
        exit 1
    fi

    case "${1-}" in
        'install')
            [ $# -le 2 ] || usage

            case "${2-}" in
                'all')
                    set -- "$1" '|client|server|'
                    ;;
                '')
                    set -- "$1" '|client|'
                    ;;
                'client'|'server')
                    set -- "$1" "|$2|"
                    ;;
                *)
                    ! : || usage
                    ;;
            esac

            if [ "$this" -ef "$install_to" ]; then
                echo >&2 "$prog_name: already installed"
                exit 0
            fi
            ;;
        'update')
            update='1'

            if [ ! "$this" -ef "$install_to" ]; then
                echo >&2 "$prog_name: not installed. Hint: run '$install_to'."
                exit 0
            fi

            set -- "$1" '|update|'
            put__skip_existing="$2"
            ;;
        *)
            ! : || usage
            ;;
    esac

    # Sudoers(5) template
    sudoers_line_runas="%$certmgr ALL=($runas:$runas) SETENV:NOPASSWD: "
    sudoers_line_root="$runas ALL=(root:root) SETENV:NOPASSWD: "
    sudoers_progs=''

    # Add $certmgr group whose members able to $runas certbot via sudo(1)
    groupadd -r -f "$certmgr"

    # Add $runas unprivileged user and group
    homedir='/var/lib/letsencrypt'

    # Usage: _usermod <runas> <home>
    _usermod()
    {
        local func="${FUNCNAME:-_usermod}"

        local runas="${1:?missing 1st arg to ${func}() (<runas>)}"
        local home="${2:?missing 2d arg to ${func}() (<home>)}"
        local comment='Lets Encrypt user'
        local shell="${shell:-/bin/sh}"
        local cmd='groupadd' args='-r -f'

        # Assert in case there is no shell exists.
        if [ ! -x "$shell" ]; then
            echo >&2 "$prog_name: \"$shell\" interpreter doesn't executable"
            exit 1
        fi

        # groupadd
        "$cmd" $args "$runas"

        # useradd or usermod
        if [ -n "$(id -u "$runas" 2>/dev/null)" ]; then
            cmd='usermod'
            args=''
        else
            cmd='useradd'
            args='-r -M'
        fi

        "$cmd" $args \
            -g "$runas" \
            -G "$certmgr" \
            -d "$home" \
            -c "$comment" \
            -s "$shell" \
            "$runas" \
            #
    }
    eval '_usermod "$runas" "$homedir"'

    if [ -n "${2##*|update|*}" ]; then
        # Install self
        install -D -m 0750 -p -g "$certmgr" "$this" "$install_to"
    else
        # Update ownership and permissions on self
        new "$install_to" 'root' "$certmgr" 0750
    fi

    # Working directory
    t='/etc/letsencrypt/' && new "$t"

    # Home directory. Must be writable (e.g. to put .certbot.lock)
    t="$homedir/"         && new "$t" 'root' "$runas" 3775

    # Letsencrypt user XDG .config, .cache and .local directories
    t="$homedir/.config/" && new "$t" 'root' "$runas" 2755
    t="$t/letsencrypt/"   && new "$t" 'root' "$runas" 2750

    configdir="$(cd "$t" && echo "$PWD")"

    t="$homedir/.cache/"  && new "$t" 'root' "$runas" 2755
    t="$t/letsencrypt/"   && new "$t" 'root' "$runas" 3730

    cachedir="$(cd "$t" && echo "$PWD")"

    t="$homedir/.local/"  && new "$t" 'root' "$runas" 2755
    t="$t/bin/"           && new "$t" 'root' "$runas" 2750

    ln -sf '.local/bin' "$homedir/bin"

    if [ -z "${2##*|server|*}" ]; then
        # certbotsh-publish (deploy hook)
        t="${t}certbotsh-publish" && r="$(relative_path "$install_to" "$t")"
        ln -sf "$r" "$t"

        # Directory to publish PKCS#12 files
        t="$homedir/.htdocs/" && new "$t" 'root' "$runas" 3731
        htdocsdir="${t%/}"

        # Letsencrypt user extra directory
        t="$homedir/extra/" && new "$t" "$runas" "$runas" 0755
        extradir="$(cd "$t" && echo "$PWD")"

        # Write our applets configs
        publish_cfg

        # Configure http server
        server_http_conf "${httpd_hostname-}" "${httpd_domain-}"

        # Configure logrotate
        server_log_conf

        # Configure automated renewals
        server_cron_conf

        # Extra configuration examples
        server_extra_conf

        # Write certbot and it's plugins
        cli_ini
        rfc2136_ini

        # certbot alias
        for t in $symlink_dirs; do
            [ -d "$t" ] || continue

            t="$t/certbot" && r="$(relative_path "$install_to" "$t")"
            ln -sf "$r" "$t"

            sudoers_progs="$sudoers_progs
$sudoers_line_runas$t"
        done
    fi # server

    if [ -z "${2##*|client|*}" ]; then
        # Write our applets config
        update_cfg

        # Add update crontab(8) file
        t='/etc/cron.d/'         && new "$t" 'root' 'root'
        t="${t}certbotsh-update" && put "$t" <<EOF
# Periodically run update
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 */6 * * * ${runas} sleep \$((\$$ \% 3600)); certbotsh-update
EOF
        new "$t" 'root' 'root' 0644

        # .curlrc
        t="$homedir/.curlrc"     && put "$t" <<EOF
## Auth method, username and password must match server parameters
#digest
#user = "${runas}:<changeme>"
EOF
        new "$t" 'root' "$runas" 0640

        # .wgetrc
        t="$homedir/.wgetrc"     && put "$t" <<EOF
## Auth method, username and password must match server parameters
#http-user = ${runas}
#http-password = <changeme>
EOF
        new "$t" 'root' "$runas" 0640

        # applets
        for t in $symlink_dirs; do
            [ -d "$t" ] || continue

            t="$t/certbotsh-update" && r="$(relative_path "$install_to" "$t")"
            ln -sf "$r" "$t"

            sudoers_progs="$sudoers_progs
$sudoers_line_runas$t"
        done
        for t in $symlink_dirs; do
            [ -d "$t" ] || continue

            t="$t/certbotsh-hook" && r="$(relative_path "$install_to" "$t")"
            ln -sf "$r" "$t"

            sudoers_progs="$sudoers_progs
$sudoers_line_root$t"
        done
    fi # client

    # sudoers(5) file
    t='/etc/sudoers.d/certbot'
    echo "$sudoers_progs" | put "$t" && new "$t" 'root' 'root' 0640
} # installer

# Usage: applet ...
applet()
{
    # Requires: id(1), sudo(8) and applet specific utils (see _${real_prog}())
    #
    # Config:  $this_prog, $runas, $install_to,
    # Runtime: $this, $this_dir, $prog_name

    # Usage: cookie_get {<cookie_var>|''} <name>
    cookie_get()
    {
        local func="${FUNCNAME:-cookie_set}"

        local cookie_var="${1:-cookie}" && shift
        eval "local cookie=\"\${$cookie_var-}\"" && cookie="${cookie%;}"
        local name="${1:?missing 2d arg to ${func} (<name>)}" && shift

        local t="$cookie" && t="${t:+;$t;}"
        local nw="$name=*"

        if [ -z "${t##*;$nw;*}" ]; then
            t="${t#*;${name}=}" && t="${t%%;*}"
        else
            t=''
        fi

        echo "$name='$t'"
    }

    # Usage: _cookie_mod {<cookie_var>|''} <name> [<val>...]
    _cookie_mod()
    {
        local func="${func:-_cookie_mod}"

        local cookie_var="${1:-cookie}" && shift
        eval "local cookie=\"\${$cookie_var-}\"" && cookie="${cookie%;}"
        local name="${1:?missing 2d arg to ${func} (<name>)}" && shift

        local t="$cookie" && t="${t:+;$t;}"
        local nw="$name=*"

        if [ -z "${t##*;$nw;*}" ]; then
            local a="${t%;$nw;*};"
            local b=";${t#*;$nw;}"

            if [ -n "${old-}" ]; then
                t="${t#$a}" && t="${t%$b}" && echo "$name='${t#${name}=}'"
            fi

            cookie="${a#;}${b#;}" && cookie="${cookie%;}"
        fi

        if [ -n "${new-}" ]; then
            cookie="${cookie:+$cookie;}${name}=${*-}"
        fi

        echo "$cookie_var='$cookie'"
    }

    # Usage: cookie_add {<cookie_var>|''} <name> [<val>...]
    cookie_add()
    {
        local func="${FUNCNAME:-cookie_add}"
        local new=1 old=''
        _cookie_mod "$@"
    }

    # Usage: cookie_del {<cookie_var>|''} <name>
    cookie_del()
    {
        local func="${FUNCNAME:-cookie_del}"
        local new='' old=''
        _cookie_mod "$@"
    }

    # Usage: cookie_push {<cookie_var>|''} <name>
    cookie_push()
    {
        local func="${FUNCNAME:-cookie_push}"
        local new=1 old=1
        _cookie_mod "$@"
    }

    # Usage: cookie_pull {<cookie_var>|''} <name>
    cookie_pull()
    {
        local func="${FUNCNAME:-cookie_pull}"
        local new='' old=1
        _cookie_mod "$@"
    }

    # Usage: cookie_merge {<cookie_var>|''} [name1=val1;name2=val2 ...]
    cookie_merge()
    {
        local func="${FUNCNAME:-cookie_merge}"

        local cookie_var="${1-}" && shift

        local new=1 old=''

        local ifs="$IFS" && IFS=';' && set -- $* && IFS="$ifs"

        while [ $# -gt 0 ]; do
            if [ -n "$1" ]; then
                eval "$(_cookie_mod "$cookie_var" "${1%%=*}" "${1#*=}")"
            fi
            shift
        done
    }

    # Usage: make_shlvar_name <str>
    make_shlvar_name()
    {
        local func="${FUNCNAME:-make_shlvar_name}"

        local str="${1:?missing 1st arg to ${func}() (<str>)}"

        echo "${str}" | sed -e 's/\W/_/g' || return
    }

    # Usage: get_ini <file>
    get_ini()
    {
        local func="${FUNCNAME:-publish}"

        local file="${1:?missing 1st arg to ${func}() (<file>)}"
        shift

        # Make sure config is readable and non-empty
        local _ini=".config/letsencrypt/$file"
        local ini="$HOME/${_ini}"

        if [ ! -r "$ini" ]; then
            echo >&2 "$prog_name: $ini isn't readable by $runas"
            return 1
        fi
        if [ ! -s "$ini" ]; then
            echo >&2 "$prog_name: $ini is empty"
            return 1
        fi

        echo "$ini"
    }

    # do_exec <ini> ...
    do_exec()
    {
        local func="${FUNCNAME:-publish}"

        local ini="${1:?missing 1st arg to ${func}() (<ini>)}"
        shift

        eval $(
            # Execute in new shell to eliminate functions
            real_prog="$(command -v '$real_prog')" || exit

            if [ ! -x "$real_prog" ]; then
                echo >&2 "$prog_name: \"$real_prog\" is not executable"
                exit 1
            fi

            if [ "$real_prog" -ef "$this" ]; then
                echo >&2 "$prog_name: real program \"$real_prog\" and alias \"$this\" are the same"
                exit 1
            fi

            echo "real_prog='$real_prog'"
        )

        IN_USER_SH="$IN_USER_SH" exec "$real_prog" "$@"
    } # do_exec

    # Usage: _certbot <ini> ...
    _certbot()
    {
        # Requires: certbot

        do_exec "$@"
    }

    # Usage: _publish <ini> ...
    _publish()
    {
        # Requires: mktemp(1), mv(1), rm(1), ln(1), chmod(1),
        #           getent(1), openssl(1), pwgen(1)

        local func="${FUNCNAME:-_publish}"

        local ini="${1:?missing 1st arg to ${func}() (<ini>)}" && shift
        ini="$(get_ini "$ini")" || return

        ## Source and sanity check the config
        eval $(
            # Any shell code sourced from configuration file $runas
            # user in a subshell that effectively restricts it.
            if . "$ini" >/dev/null; then
                echo "local pubdir='${pubdir-}'"
                echo "local pwgen_opts='${pwgen_opts-}'"
                echo "local pkcs12_opts='${pkcs12_opts-}'"
            else
                echo "return $?"
            fi
        )

        # Directory where live certificate lineages published
        pubdir=${pubdir:-~/.htdocs}
        # pwgen(1) options
        pwgen_opts="${pwgen_opts:--ncysB1 16}"
        # openssl pkcs(1) options
        pkcs12_opts="${pkcs12_opts:-\
            -keypbe aes-256-cbc \
            -certpbe aes-256-cbc \
            -macalg sha256 \
        }"

        if [ ! -d "$pubdir" ]; then
            echo >&2 "$prog_name: no public directory \"$pubdir\" exists"
            exit 1
        fi

        ## Enter renewed certificate lineage

        local domain pf
        local t tf td

        # Usage: exit_handler
        exit_handler()
        {
            local rc=$?

            # Do not interrupt exit hander
            set +e

            # Temporary output directory
            [ -z "${td-}" ] || rm -rf "$td"

            return $rc
        }
        trap 'exit_handler' EXIT

        cd "$RENEWED_LINEAGE"

        pf='privkey.passphrase'
        if ! [ -r "$pf" -a -s "$pf" ]; then
            rm -f "$pf" ||:
            pwgen $pwgen_opts -r \'\" >"$pf" && chmod o= "$pf"
        fi

        domain="${RENEWED_LINEAGE##*/}"

        t="$pubdir/$domain"

        td="$(mktemp -d "$pubdir/.$domain.XXXXXXXX")"
        tf="$td/$domain.p12"

        # Make PKCS#12 file
        openssl pkcs12 \
            $pkcs12_opts \
            -export \
            -certfile 'chain.pem' -inkey 'privkey.pem' -in 'cert.pem' \
            -passout "file:$pf" -out "$tf" \
            #

        # Ensure file is readable
        chmod 0644 "$tf" ||:

        # Add to directory with PKCS#12 file symlinks to IP address(es) from
        {
            # ... DNS resource records (RRs) for hostname
            getent ahosts "$domain"
            # ... ".sticky" subdirectory
            if cd "$t/.sticky" 2>/dev/null; then
                for ip in *; do
                    # It has invalid IP/IPv6 address symbols?
                    [ -n "${ip##*[^0-9a-fA-F:.]*}" ] || continue

                    if [ -L "$ip" ]; then
                       # It is a symlink pointing to /dev/null?
                       [ "$ip" -ef /dev/null ] || continue
                       echo "-$ip"
                       ln -sf /dev/null "$td/.sticky/$ip"
                    else
                       # It is a regular file?
                       [ -f "$ip" ] || continue
                       echo "$ip"
                       install -D -m 0644 /dev/null "$td/.sticky/$ip"
                    fi
                done
                cd - >/dev/null
            fi
        } |\
        while read ip _; do
            if [ -n "${ip##-*}" ]; then
                ip="$td/$ip" && [ "$ip" -ef "$td" ] || ln -sf . "$ip"
            else
                ip="$td/${ip#-}" && rm -f "$ip"
            fi
        done

        # Install new (temporary) data
        mv -f "$t" "$td" 2>/dev/null ||:
        if mv -f "$td" "$t"; then
            rm -rf "$t/$domain" && chmod 0755 "$t" && td='' ||:
        else
            mv -f "$td/$domain" "$t" 2>/dev/null ||:
        fi

        ## Leave renewed certificate lineage
        cd - >/dev/null 2>&1

        exit 0
    } # _publish

    # Usage: _update <ini> ...
    _update()
    {
        # Requires: /bin/sh, install(1), mktemp(1), mv(1), rm(1), chmod(1),
        #           cmp(1), openssl(1), wget(1)/curl(1)

        local func="${FUNCNAME:-_update}"

        local ini="${1:?missing 1st arg to ${func}() (<ini>)}" && shift
        ini="$(get_ini "$ini")" || return

        # Usage: le_pkcs12_to_pem <p12> <path> [<passphrase>]
        le_pkcs12_to_pem()
        {
            local func="${FUNCNAME:-le_pkcs12_to_pem}"

            local p12="${1:?missing 1st arg to ${func}() <p12>}"
            local path="${2:?missing 2d arg to ${func}() <path>}"
            local ph="${3-}"

            local cert_pem='-clcerts -nokeys'
            local chain_pem='-cacerts -nokeys'
            local fullchain_pem='-nokeys'
            local privkey_pem='-nocerts'

            local p args

            for p in 'cert' 'chain' 'fullchain' 'privkey'; do
                # Take appropriate arguments to control output
                eval "args=\"\$${p}_pem\""

                # Passphrase is passed via environment
                ph="$ph" \
                openssl pkcs12 \
                    $args \
                    -passin 'env:ph' \
                    -in "$p12" \
                    -nodes \
                    -out "$path/$p.pem" >/dev/null 2>&1 || return
            done

            # privkey.pem
            chmod 0600 "$path/$p.pem" || return

            return 0
        }

        # Usage: get_cert_var <cert> <name> [<nofail>]
        get_cert_var()
        {
            local func="${FUNCNAME:-get_cert_var}"

            local c="${1:?missing 1st arg to ${func}() (<cert>)}"
            local n="${2:?missing 2d arg to ${func}() (<name>)}"
            local q="${3-}"

            local t v="${c}_${n}"
            local rc=0

            eval "t=\"\${$v-}\" && [ -n \"\$t\" ]" || rc=$?
            echo "local $n='$t'"

            if [ $rc -ne 0 ]; then
                [ -n "$q" ] ||
                    echo >&2 "$prog_name: var \"$v\" is unset or empty"
                echo '! :'
                return 1
            fi
        }

        # Usage: do_fetch <file> <url>
        do_fetch()
        {
            local func="${FUNCNAME:-do_fetch}"

            local file="${1:?missing 1st arg to ${func}() (<file>)}" && shift
            local url="${1:?missing 2d arg to ${func}() (<url>)}" && shift

            # Hide @cookie variable contents from curl(1) for security.
            # It is used as communication mechanism by this environment
            # and hooks and may contain security sensitive information.
            # Having access to it by program with network access is a risk.
            local cookie=''

            # Additional arguments (e.g. username and password for HTTP
            # authentication) should be configured through utility specific
            # configuration file (e.g. ~$runas/.wgetrc or ~$runas/.curlrc).
            local wget_args='-q -O %s %s'
            local curl_args='-s -o %s %s'
            local args

            local fetch
            for fetch in \
                'wget' \
                'curl' \
                #
            do
                # Installed?
                type "$fetch" >/dev/null 2>&1 || continue
                # Have args for it?
                eval "args=\"\${${fetch}_args-}\""
                [ -n "$args" ] || continue
                # Make command line for $fetch
                args="$(printf -- "$args" "$file" "$url")" || continue
                # Fetch $file from $url
                "$fetch" $args && return ||:
            done

            return 1
        }

        # Usage: do_hook <name> <cmd> ...
        do_hook()
        {
            local func="${FUNCNAME:-do_hook}"

            local name="${1:?missing 1st arg to ${func}() (<name>)}" && shift
            local cmd="${1-}"
            [ -n "$cmd" ] || return 0
            shift

            local rc=125

            # Strictly check input from hook execution to avoid injection
            # of commands in our execution. Only accept and set via "eval"
            # specific variables that known to be safe/useful in our
            # environment.

            eval $(
                {
                    "$shell" -c "$cmd" "$name" "$@"
                    echo "rc=$?"
                } |\
                while read vv; do
                    # cookie=
                    if v="${vv##cookie=}" && [ "$v" != "$vv" ]; then
                        v="${v#\'}" && v="${v%\'}"
                        # No single quotes in cookie value
                        if [ -n "${v##*\'*}" ]; then
                            echo "cookie_merge 'cookie' '$v';"
                        fi
                    # rc=$?
                    elif v="${vv##rc=}" && [ "$v" != "$vv" ]; then
                        v="${v#\'}" && v="${v%\'}"
                        # Make sure return code is valid (could be injected)
                        if [ "$v" -ge 0 -o "$v" -lt 0 ] 2>/dev/null; then
                            echo "rc='$v';"
                        fi
                    fi
                done && echo "cookie=\"\$cookie\""
            )

            return $rc
        }

        ## Source and sanity check the config
        eval $(
            # Any shell code sourced from configuration file $runas
            # user in a subshell that effectively restricts it.
            if . "$ini" >/dev/null; then
                _certs=''

                for c in $certs; do
                    # Skip invalid shell variable names
                    [ -n "${c##[0-9]*}" ] || continue
                    [ -n "${c##*[^[:alnum:]_]*}" ] || continue

                    for n in          \
                        'url'         \
                        'domain'      \
                        'ph'          \
                        'pre_hook'    \
                        'deploy_hook' \
                        'post_hook'   \
                        #
                    do
                        eval "echo \"local \${c}_\${n}='\${${c}_${n}-}'\""
                    done

                    _certs="${_certs:+$_certs }${c}"
                done

                echo "local certs='${_certs}'"
            else
                echo "return $?"
            fi
        )

        if [ -z "$certs" ]; then
            echo >&2 "$prog_name: no certificates defined in $ini"
            exit 1
        fi

        local datadir p12_dir live_dir shell

        # Let's encrypt cache directory
        datadir=~/.cache/letsencrypt

        # Cache directory to store .p12 files locally for compare
        p12_dir="$datadir/p12"
        if [ ! -d "$p12_dir" ]; then
            rm -f "$p12_dir" ||:
            install -d "$p12_dir"
        fi
        # Live directory for certbot compatibility to put PEM files
        live_dir='/etc/letsencrypt/live'
        if [ ! -d "$live_dir" ]; then
            rm -f "$live_dir" ||:
            install -d "$live_dir"
        fi

        exit_handler()
        {
            local rc=$?

            # Do not interrupt exit hander
            set +e

            # Temporary .p12 file
            [ -z "${tf-}" ] || rm -f "$tf"
            # Temporary .pem files directory
            [ -z "${td-}" ] || rm -rf "$td"

            return $rc
        }
        trap 'exit_handler' EXIT

        local url domain ph
        local c p t tf td rc
        local pre_hook deploy_hook post_hook

        # Use "export" since /bin/dash does not mark for export
        # environment variables prefixed function name (i.e.
        # RENEWED_LINEAGE= RENEWED_DOMAINS= do_hook ... "$cmd"
        # does not see variables, while they seen in do_hook()).

        # Provide compatibility with certbot hooks
        local RENEWED_LINEAGE RENEWED_DOMAINS
        export RENEWED_LINEAGE RENEWED_DOMAINS
        # Make sure cookie variable visible to hooks
        local cookie=''
        export cookie

        for c in $certs; do
            # Get domain variable
            eval "$(get_cert_var "$c" 'domain') || continue"
            # ... skip if certbot managed
            t="$live_dir/$domain"
            [ ! -L "$t/privkey.pem" ] || continue

            # Get other associated variables values
            eval "$(get_cert_var "$c" 'url') || continue"
            eval "$(get_cert_var "$c" 'ph') || continue"
            eval "$(get_cert_var "$c" 'pre_hook'    q) ||:"
            eval "$(get_cert_var "$c" 'deploy_hook' q) ||:"
            eval "$(get_cert_var "$c" 'post_hook'   q) ||:"

            # pre
            RENEWED_LINEAGE=
            RENEWED_DOMAINS=
            # @cookie preserved across certs to support single
            # stop/start for services with multiple certificates
            do_hook 'pre_hook' "$pre_hook" || continue

            # Fetch PKCS#12 file to check for update
            p="$domain.p12"
            tf="$(mktemp "$p12_dir/.$p.XXXXXXXX")"

            if do_fetch "$tf" "${url%/*.p12}/$p"; then
                # Is it differs from cached copy?
                if ! cmp -s "$tf" "$p12_dir/$p"; then
                    # Unpack it
                    td="$(mktemp -d "$live_dir/.$domain.XXXXXXXX")"

                    if le_pkcs12_to_pem "$tf" "$td" "$ph"; then
                        # Install new (temporary) data

                        # ... live
                        mv -f "$t" "$td" 2>/dev/null ||:
                        if mv -f "$td" "$t"; then
                            rc=0

                            # deploy
                            RENEWED_LINEAGE="$t"
                            RENEWED_DOMAINS="$domain"
                            do_hook 'deploy_hook' "$deploy_hook" || rc=$?

                            [ $rc -eq 0 ] || mv -f "$t" "$td" ||:
                        else
                            rc=$?
                        fi

                        if [ $rc -eq 0 ]; then
                            rm -rf "$t/$domain" && chmod 0755 "$t" ||:
                        else
                            mv -f "$td/$domain" "$t" 2>/dev/null ||:
                        fi

                        # ... p12
                        [ $rc -eq 0 ] && mv -f "$tf" "$p12_dir/$p" && tf='' ||:
                    fi

                    # Cleanup temporary directory
                    rm -rf "$td" && td='' ||:
                fi
            fi

            # Cleanup temporary file
            rm -f "$tf" && tf='' ||:

            # post
            RENEWED_LINEAGE=
            RENEWED_DOMAINS=
            do_hook 'post_hook' "$post_hook" ||:
        done

        exit 0
    } # _update

    # Usage: _hook ...
    _hook()
    {
        # Requires: cat(1), sed(1), service(8)

        local func="${FUNCNAME:-_hook}"

        local ini="${1:?missing 1st arg to ${func}() (<ini>)}" && shift

        local _registered_services
        local action
        local conf_dir conf_file pki_dir

        #### Helpers

        _registered_services='|'

        # Usage: register_service <service>
        register_service()
        {
            [ -n "${1-}" ] || return

            [ -z "${_registered_services##*|${1}|*}" ] ||
                _registered_services="${_registered_services}${1}|"
        }

        # Usage: unregister_service <service>
        unregister_service()
        {
            local s="${1-}"
            local a="${_registered_services%%|${s}|*}"
            local b="${_registered_services##*|${s}|}"
            _registered_services="$a|$b"
        }

        # Usage: is_registered_service <service>
        is_registered_service()
        {
            [ -n "${1-}" ] || return

            [ -z "${_registered_services##*|${1}|*}" ] || return
        }

        # Usage: registered_services_list
        registered_services_list()
        {
            local _rs="${_registered_services#|}" && _rs="${_rs%|}"
            local ifs="$IFS" && IFS='|' && set -- ${_rs} && IFS="$ifs"
            printf "'%s'\n" "$@"
        }

        # Usage: fatal_insane_config <action> <service>
        fatal_insane_config()
        {
            if [ "$1" = 'deploy' ]; then
                # Deploy hook caller should supply them
                if [ -z "${RENEWED_LINEAGE-}" ]; then
                    echo >&2 "$prog_name: $1: $2: RENEWED_LINEAGE unset"
                    exit 1
                fi
                if [ -z "${RENEWED_DOMAINS-}" ]; then
                    echo >&2 "$prog_name: $1: $2: RENEWED_DOMAINS unset"
                    exit 1
                fi
            else
                # Other hooks should not supply them
                if [ -n "${RENEWED_LINEAGE:+x}" ]; then
                    echo >&2 "$prog_name: $1: $2: RENEWED_LINEAGE is set"
                    exit 1
                fi
                if [ -n "${RENEWED_DOMAINS:+x}" ]; then
                    echo >&2 "$prog_name: $1: $2: RENEWED_DOMAINS is set"
                    exit 1
                fi
            fi
        }

        #### Services

        ## lighttpd

        # Usage: lighttpd_desc_fn <service>
        lighttpd_desc_fn()
        {
            echo 'Secure, fast, compliant and very flexible web-server'
        }
        local lighttpd_desc='lighttpd_desc_fn'

        # Usage: _lighttpd_register
        _lighttpd_register()
        {
            register_service 'lighttpd'
        }
        _lighttpd_register

        ## nginx

        # Usage: nginx_desc_fn <service>
        nginx_desc_fn()
        {
            echo 'A high performance web server and reverse proxy server'
        }
        local nginx_desc='nginx_desc_fn'

        # Usage: _nginx_register
        _nginx_register()
        {
            register_service 'nginx'
        }
        _nginx_register

        ## apache2

        # Usage: apache2_desc_fn <service>
        apache2_desc_fn()
        {
            echo 'The Apache HTTP Server is a powerful, efficient, and extensible web server'
        }
        local apache2_desc='apache2_desc_fn'

        # Usage: _apache2_register
        _apache2_register()
        {
            register_service 'apache2'
        }
        _apache2_register

        ## vsftpd

        # Usage: vsftpd_desc_fn <service>
        vsftpd_desc_fn()
        {
            echo 'vsftpd is a Very Secure FTP daemon'
        }
        local vsftpd_desc='vsftpd_desc_fn'

        # Usage: _vsftpd_register
        _vsftpd_register()
        {
            register_service 'vsftpd'
        }
        _vsftpd_register

        #### Main

        # Usage: do_hook <hook> <service> ...
        do_hook()
        {
            local h="$1" && shift
            local s="$1" && shift

            # Get service from systemd(1) instance
            s="${s%@*}"

            # Skip invalid shell variable names
            [ -n "${s##[0-9]*}" ] || continue
            [ -n "${s##*[^[:alnum:]_]*}" ] || continue

            eval "local fn=\"\${${s}_${h}-}\""
            [ -z "$fn" ] || "$fn" "$@" || return
        }

        # Usage: pre <service> ...
        pre()
        {
            local rc=0

            do_hook 'pre' "$@" || rc=$?
            [ $rc -ge 0 ] || return 0    # rc < 0
            [ $rc -eq 0 ] || return $rc  # rc > 0

            local running=0
            local cookie

            if service "$1" status; then
                service "$1" stop && running=1 || rc=$?
            fi >/dev/null 2>&1

            cookie_add 'cookie' "running_$(make_shlvar_name "$1")" "$running"

            return $rc
        }

        # Usage: deploy <service> ...
        deploy()
        {
            local rc=0

            do_hook 'deploy' "$@" || rc=$?
            [ $rc -le 0 ] || return $rc  # rc > 0

            local cookie="${cookie-}"
            cookie_add 'cookie' "deploy_$(make_shlvar_name "$1")" '1'

            [ $rc -eq 0 ] || return 0    # rc < 0

            return $rc
        }

        # Usage: post <service> ...
        post()
        {
            local rc=0

            do_hook 'post' "$@" || rc=$?
            [ $rc -ge 0 ] || return 0    # rc < 0
            [ $rc -eq 0 ] || return $rc  # rc > 0

            # Usage: get_service_var <var> <service>
            get_service_var()
            {
                cookie_get 'cookie' "${1}_$(make_shlvar_name "$2")" | {
                    read d
                    d="${d#*\'}"
                    d="${d%\'}"
                    echo "${1}='$d'"
                }
            }

            local running deploy
            local cookie="${cookie-}"

            eval "$(get_service_var 'running' "$1")"

            if [ -z "$running" ]; then
                running=0

                eval "$(get_service_var 'deploy' "$1")"

                if [ ${deploy:-0} -gt 0 ]; then
                    if service "$1" status; then
                        service "$1" stop && running=1 || rc=$?
                    fi
                fi >/dev/null 2>&1
            fi

            if [ $running -gt 0 ]; then
                if service "$1" start &&
                   service "$1" status; then
                    :
                else
                    rc=$?
                    running=0
                fi
            fi >/dev/null 2>&1

            cookie_add 'cookie' "running_$(make_shlvar_name "$1")" "$running"

            return $rc
        }

        # Usage: help <service> ...
        help()
        {
            local rc=0

            do_hook 'help' "$@" || rc=$?
            [ $rc -ge 0 ] || return 0    # rc < 0
            [ $rc -eq 0 ] || return $rc  # rc > 0

            cat <<'_EOF'
To maintain compatibility with certbot and support SSL/TLS configuration
for virtually any service type assume that configuration references
certificate files in /etc/letsencrypt/live/<domain> either directly or
indirectly via symlink that points to this location.

For example it might be useful to have symlink to /etc/letsencrypt/live
in service configuration directory like following for lighttpd:

    /etc/lighttpd/pki -> /etc/letsencrypt/live

and use that symlink in service configuration files:

   ssl.pemfile = "/etc/lighttpd/pki/example.com/cert.pem"
   ssl.privkey = "/etc/lighttpd/pki/example.com/privkey.pem"
   ssl.ca-file = "/etc/lighttpd/pki/example.com/chain.pem"

Another example might be useful when multiple virtual hosts with certs from
different authorities served by same httpd instance:

   /etc/lighttpd/pki/
                     wildcard             -> example.com
                     example.com          -> ../../live/example.com
                     www.example.com      -> ../../live/www.example.com
                     w01.example.com/     # Non LetsEncrypt CA
                     w02.example.com/     # Non LetsEncrypt CA

   /etc/letsencrypt/live/
                         example.com/     # LetsEncrypt CA
                         www.example.com/ # LetsEncrypt CA

In this case LetsEncrypt served domains symlinked to /etc/letsencrypt/live.

By default service(8) wrapper is used in pre/deploy/post hooks to support
multiple platforms with different system/services init manager (e.g. systemd,
sysvinit, upstart).

Custom service hooks can be implemented that complements or replaces generic
hooks functionality when specific actions required to install/update
certificates.
_EOF
            return $rc
        }

        # Usage: list
        list()
        {
            eval set -- $(registered_services_list)
            echo 'Supported services:'
            echo "\
  <service> - Any service(8) supporting start, stop and status commands
"
            while [ $# -gt 0 ]; do
                echo "  ${1} - $(eval \$${1}_desc "${1}")"
                shift
            done
        }

        # Usage: usage
        usage()
        {
            local rc=$?
            echo >&2 "usage: $prog_name { {pre|deploy|post|help} <service> ... | list }"
            exit $rc
        }

        # See how we've called
        case "${action:=${1-}}" in
           'pre'|'deploy'|'post'|'help')
               # Service name
               [ -n "${2-}" ] || usage
               # Make sure service config is sane
               [ "$1" = 'help' ] || fatal_insane_config "$1" "$2"
               ;;
           'list'|'usage')
               # No extra args
               [ $# -eq 1 ] || usage
               ;;
           *)
               ! : || usage
               ;;
        esac
        shift

        # Execute action
        "$action" "$@"

        # Exit explicitly
        exit
    } # _hook

    if [ ! "$this" -ef "$install_to" ]; then
        echo >&2 "$prog_name: not installed"
        exit 1
    fi

    # Make sure we $runas user
    if [ "$(id -u -n)" != "$runas" ]; then
        if [ -n "${IN_USER_SH-x}" ]; then
            local IN_USER_SH=
        else
            echo >&2 "$prog_name: not running as \"$runas\" user after sudo(8)"
            exit 1
        fi

        {
            # Do not pass these variables directly via sudo(8) command line
            # arguments as they (e.g. cookie) may contain security sensitive
            # information. At this moment only two variables must and safe to
            # be passed via sudo(8) command line: $runas and $IN_USER_SH.
            #
            # Sanity check variable value and enclose it into single quotas to
            # avoid injection in all cases (e.g. compromised $runas user has
            # configured sudoers(5) entry that allows them to execute
            # certbotsh-hook that accepts runas='root' from environment).

            # Usage: echo_vv <var>
            echo_vv()
            {
                local var="${1-}"
                [ -n "$var" ] || return 0

                eval "
                    if [ -n \"\${$var+x}\" ]; then
                        local val=\"\$$var\"
                        # No single quotes in value
                        if [ -n \"\${val##*\\'*}\" ]; then
                            echo \"$var='\$val'\"
                        fi
                    fi
                "
            }

            echo_vv 'RENEWED_LINEAGE'
            echo_vv 'RENEWED_DOMAINS'
            echo_vv 'cookie'

        } | sudo -H -u "$runas" runas="$runas" IN_USER_SH="$$" "$this" "$@"

        exit
    fi

    local t

    if [ "${IN_USER_SH-}" != "$this" ]; then
        local IN_USER_SH="${IN_USER_SH-}"

        # Fetch and evaluate commands (variable assignments) from standard input
        # is safe as we $runas user that makes command injection meaningless.
        if [ -n "${IN_USER_SH##*[^0-9]*}" ] &&
           kill -0 "$IN_USER_SH" 2>/dev/null
        then
            while read -r t; do
                eval "$t"
            done
        fi

        IN_USER_SH="$this"
    else
        echo >&2 "$prog_name: exec loop detected: failed"
        exit 1
    fi

    local real_name ini

    real_prog="${prog_name#certbotsh-}"
    case "$real_prog" in
        # functions
        'publish'|'update'|'hook')
            ini="$real_prog.cfg"

            # Make sure symlink target directories always in $PATH for applets
            PATH=":$PATH:"
            for t in $symlink_dirs; do
                [ -d "$t" ] || continue
                [ -z "${PATH##*:$t:*}" ] || PATH=":$t$PATH"
            done
            PATH="${PATH#:}" && PATH="${PATH%:}"
            ;;
        # aliases
        'certbot')
            ini='cli.ini'

            # Make sure NO symlink target directories in $PATH for aliases
            PATH=":$PATH:"
            for t in $symlink_dirs; do
                [ -z "${PATH##*:$t:*}" ] || continue
                PATH="${t%:$t:*}:" && PATH="$PATH${t#*:$t:}"
            done
            PATH="${PATH#:}" && PATH="${PATH%:}"
            ;;
        *)
            echo >&2 "$this_prog: unknown applet \"$prog_name\""
            ;;
    esac

    # Call applet (function)
    "_${real_prog}" "$ini" "$@"

    # Never reached since applet function MUST never return
    exit 125
} # applet

################################################################################

#set -x
set -e
set -u

if [ ! -e "$0" -o "$0" -ef "/proc/$$/exe" ]; then
    # Executed script is
    #  a) read from stdin through pipe
    #  b) specified via -c option
    #  d) sourced
    this="$this_prog"
    this_dir='./'
else
    # Executed script exists and it's inode differs
    # from process exe symlink (Linux specific)
    this="$0"
    this_dir="${this%/*}/"
fi
this_dir="$(cd "$this_dir" && echo "$PWD")"

# Set program name
prog_name="${this##*/}"

this="$this_dir/$prog_name"

# Installing or running applet?
if [ ! -L "$this" ]; then
    installer "$@"
else
    applet "$@"
fi
