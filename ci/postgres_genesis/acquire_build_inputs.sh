#!/bin/bash
# Hosted disposable container only. No source build command is permitted here.
set -euo pipefail
umask 022
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=UTC DEBIAN_FRONTEND=noninteractive

phase() { printf '%s\n' "$1" > /out/phase.txt; }
finish() {
    result=$?
    if [ "$result" -eq 0 ]; then printf 'success\n' > /out/acquisition-outcome.txt;
    else
        printf 'failure\n' > /out/acquisition-outcome.txt
        if [ -f /tmp/academy-apt.conf ]; then
            apt-cache -c /tmp/academy-apt.conf policy libc6-dev gcc-14 g++-14 llvm-19-dev clang-19 > /out/anchor-candidates.txt 2>/dev/null || true
        fi
    fi
}
trap finish EXIT
phase base_preflight
test "$(id -u)" = 0
test -d /inputs/source
test ! -e /out/base-bom.tsv
mkdir -p /out/debs/partial /out/apt/inherited /out/apt/lists /out/apt/keys /out/transactions /out/tools

record() {
    local name=$1
    shift
    local code=0
    "$@" > "/out/transactions/$name.txt" 2>&1 || code=$?
    printf '%s\t%s\n' "$name" "$code" >> /out/command-status.tsv
    test "$(wc -c < "/out/transactions/$name.txt")" -le 16777216
    test "$code" -eq 0
}
bom() {
    dpkg-query -W -f='${db:Status-Status}\t${binary:Package}\t${Version}\t${Architecture}\n' |
        awk -F '\t' '$1 != "installed" {exit 1} {print $2 "\t" $3 "\t" $4}' | sort
}
bom > /out/base-bom.tsv
test "$(dpkg-query -W -f='${Version}' libc6:amd64)" = '2.41-12+deb13u4'
test "$(dpkg-query -W -f='${Version}' gcc-14-base:amd64)" = '14.2.0-19'
test "$(dpkg-query -W -f='${Version}' libllvm19:amd64)" = '1:19.1.7-3+b1'
test -x /usr/bin/gpg
test -r /usr/share/keyrings/debian-archive-keyring.gpg
test -r /usr/local/share/keyrings/postgres.gpg.asc
grep -Eq '^[[:space:]]*create_main_cluster[[:space:]]*=[[:space:]]*false[[:space:]]*$' /etc/postgresql-common/createcluster.conf
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod 0755 /usr/sbin/policy-rc.d
cp /usr/sbin/policy-rc.d /out/apt/policy-rc.d
cp /etc/postgresql-common/createcluster.conf /out/apt/createcluster.conf
cut -f1 /out/base-bom.tsv | xargs -r apt-mark hold > /out/transactions/base-holds.txt

phase apt_configuration
# Only known public source configuration is copied; no auth.conf, environment or host keyring.
shopt -s nullglob
source_files=(/etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources)
for file in "${source_files[@]}"; do
    test -e "$file" || continue
    test -f "$file" && test ! -L "$file"
    cp "$file" "/out/apt/inherited/$(basename "$file")"
    awk '
      /^[[:space:]]*(#|$)/ {next}
      /^Types: deb( deb-src)?$/ {next}
      /^URIs: https?:\/\/deb.debian.org\/debian(-security)?\/?$/ {next}
      /^Suites: trixie( trixie-updates)?$/ {next}
      /^Suites: trixie-security$/ {next}
      /^Components: main$/ {next}
      /^Signed-By: \/usr\/share\/keyrings\/debian-archive-keyring.gpg$/ {next}
      /^deb(-src)? \[[[:space:]]*signed-by=\/usr\/local\/share\/keyrings\/postgres.gpg.asc[[:space:]]*\] http:\/\/apt.postgresql.org\/pub\/repos\/apt\/? trixie-pgdg main( 16)?$/ {next}
      {exit 1}
    ' "$file"
done
for file in /etc/apt/apt.conf.d/*; do
    test -f "$file" && test ! -L "$file"
    # A hook targeting our custom cache must be reviewed, never silently disabled.
    if grep -Eq '/out|[Aa]llow[Uu]nauthenticated|[Aa]llow[Ii]nsecure|[Cc]heck-[Vv]alid-[Uu]ntil.*false' "$file"; then exit 1; fi
    cp "$file" "/out/apt/inherited/config-$(basename "$file")"
done
cp /usr/share/keyrings/debian-archive-keyring.gpg /out/apt/keys/debian-archive-keyring.gpg
cp /usr/local/share/keyrings/postgres.gpg.asc /out/apt/keys/postgres.gpg.asc
mkdir /tmp/academy-empty-sourceparts
cat > /tmp/academy-sources.list <<'SOURCES'
deb [arch=amd64 signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] http://deb.debian.org/debian trixie main
deb [arch=amd64 signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] http://deb.debian.org/debian trixie-updates main
deb [arch=amd64 signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] http://deb.debian.org/debian-security trixie-security main
deb [arch=amd64 signed-by=/usr/local/share/keyrings/postgres.gpg.asc] http://apt.postgresql.org/pub/repos/apt trixie-pgdg main 16
deb-src [arch=amd64 signed-by=/usr/local/share/keyrings/postgres.gpg.asc] http://apt.postgresql.org/pub/repos/apt trixie-pgdg main
SOURCES
cat > /tmp/academy-apt.conf <<'CONFIG'
Dir::Etc::sourcelist "/tmp/academy-sources.list";
Dir::Etc::sourceparts "/tmp/academy-empty-sourceparts";
Dir::Cache::archives "/out/debs/";
Acquire::GzipIndexes "false";
Acquire::Languages "none";
Acquire::Check-Date "true";
Acquire::Check-Valid-Until "true";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
APT::Get::AllowUnauthenticated "false";
APT::Get::AllowChangeHeldPackages "false";
APT::Get::AllowDowngrades "false";
APT::Get::Remove "false";
APT::Install-Recommends "false";
APT::Install-Suggests "false";
APT::Keep-Downloaded-Packages "true";
Binary::apt-get::APT::Keep-Downloaded-Packages "true";
CONFIG
cp /tmp/academy-apt.conf /out/apt/academy-apt.conf
cp /tmp/academy-sources.list /out/apt/academy-sources.list
for key in debian pgdg; do
    home="/tmp/academy-gpg-$key"
    mkdir -m 0700 "$home"
    if [ "$key" = debian ]; then public=/out/apt/keys/debian-archive-keyring.gpg;
    else public=/out/apt/keys/postgres.gpg.asc; fi
    gpg --no-options --homedir "$home" --batch --no-auto-key-retrieve --no-autostart --auto-key-locate clear --import "$public" > /dev/null 2>&1
    gpg --no-options --homedir "$home" --batch --no-autostart --with-colons --fingerprint --list-keys 2>/dev/null |
        awk -F: '$1=="pub"{primary=1;next} $1=="sub"{primary=0} $1=="fpr" && primary{print $10;primary=0}' > "/out/apt/keys/$key-primary-fingerprints.txt"
    test -s "/out/apt/keys/$key-primary-fingerprints.txt"
done
test "$(cat /out/apt/keys/pgdg-primary-fingerprints.txt)" = B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8
apt=(apt-get -c /tmp/academy-apt.conf --no-remove --no-install-recommends)
phase apt_update
record update "${apt[@]}" -o APT::Update::Error-Mode=any update
record indextargets "${apt[@]}" indextargets
cp /out/transactions/indextargets.txt /out/apt/indextargets.txt
for file in /var/lib/apt/lists/*; do
    test -f "$file" || continue
    test ! -L "$file"
    test "$(basename "$file")" != lock || continue
    cp "$file" /out/apt/lists/
done

phase metadata_signer
# APT authenticates before bootstrap; this second verification uses only the matching immutable-base key.
for file in /out/apt/lists/*InRelease; do
    case "$(basename "$file")" in
      apt.postgresql.org_pub_repos_apt_dists_trixie-pgdg_InRelease) key=pgdg ;;
      deb.debian.org_debian_dists_trixie_InRelease|deb.debian.org_debian_dists_trixie-updates_InRelease|deb.debian.org_debian-security_dists_trixie-security_InRelease) key=debian ;;
      *) exit 1 ;;
    esac
    gpg --no-options --homedir "/tmp/academy-gpg-$key" --batch --no-auto-key-retrieve --no-autostart --auto-key-locate clear --verify "$file" > /dev/null 2>&1
done

validate_simulation() {
    awk -F '\t' '{print $1}' /out/base-bom.tsv > /tmp/academy-base-names
    awk 'NR==FNR {base[$1]=1; sub(/:amd64$/,"",$1); base[$1]=1; next}
      /^Remv / {exit 1}
      /^Inst / {if ($2 in base || $0 ~ /\[i386\]|\[arm64\]/) exit 1}
    ' /tmp/academy-base-names "$1"
}
verify_downloads_bootstrap() {
    local count=0
    local file package version architecture hash size
    for file in /out/debs/*.deb; do
        test -f "$file" && test ! -L "$file"
        count=$((count + 1))
        package=$(dpkg-deb -f "$file" Package)
        version=$(dpkg-deb -f "$file" Version)
        architecture=$(dpkg-deb -f "$file" Architecture)
        [[ "$package" =~ ^[a-z0-9][a-z0-9+.-]+$ ]]
        [[ "$version" =~ ^[A-Za-z0-9.+:~_-]+$ ]]
        [[ "$architecture" = amd64 || "$architecture" = all ]]
        hash=$(sha256sum "$file"); hash=${hash%% *}
        size=$(wc -c < "$file"); size=${size//[[:space:]]/}
        apt-cache -c /tmp/academy-apt.conf show "$package:$architecture=$version" > /tmp/academy-package-stanzas
        awk -v expected_hash="$hash" -v expected_size="$size" '
          /^SHA256: / {if ($2==expected_hash) hash=1}
          /^Size: / {if ($2==expected_size) size=1}
          END {if (!hash || !size) exit 1}
        ' /tmp/academy-package-stanzas
    done
    test "$count" -gt 0
}
install_set() {
    local label=$1
    shift
    phase "${label}_simulate"
    record "${label}-simulate" "${apt[@]}" --simulate "$@"
    validate_simulation "/out/transactions/${label}-simulate.txt"
    phase "${label}_download"
    record "${label}-download" "${apt[@]}" --yes --download-only "$@"
    verify_downloads_bootstrap
    if [ "$label" = dependencies ]; then
        phase dependency_archive_authentication
        record dependencies-verify python3 /inputs/inspect_build_source.py downloads
    fi
    phase "${label}_install"
    record "${label}-install" "${apt[@]}" --yes --no-download "$@"
    bom > /out/builder-bom.tsv
    awk -F '\t' 'NR==FNR {base[$1]=$2 FS $3; next} $1 in base {if(base[$1]!=$2 FS $3)exit 1; delete base[$1]} END {for(i in base)exit 1}' /out/base-bom.tsv /out/builder-bom.tsv
}
bootstrap=(dpkg-dev build-essential python3 libc6-dev=2.41-12+deb13u4 gcc-14=14.2.0-19 g++-14=14.2.0-19 llvm-19-dev=1:19.1.7-3+b1 clang-19=1:19.1.7-3+b1)
install_set bootstrap install "${bootstrap[@]}"
phase source_dependency_binding
record source-binding python3 /inputs/inspect_build_source.py metadata
install_set dependencies --only-source build-dep postgresql-16=16.15-1.pgdg13+2
phase closure_verification
bom > /out/builder-bom.tsv
record dpkg-audit dpkg --audit
test ! -s /out/transactions/dpkg-audit.txt
record apt-check "${apt[@]}" check
record closure python3 /inputs/inspect_build_source.py closure
phase toolchain_inventory
tools=(gcc-14 g++-14 clang-19 llvm-config-19 ld as strip make dpkg-source)
for tool in "${tools[@]}"; do
    test -x "/usr/bin/$tool"
    record "tool-$tool" "/usr/bin/$tool" --version
    sha256sum "/usr/bin/$tool" >> /out/tools/executable-hashes.txt
done
record gcc-target /usr/bin/gcc-14 -dumpmachine
record common-dev-version dpkg-query -W -f='${Version}\n' postgresql-common-dev
record common-dev-files dpkg-query -L postgresql-common-dev
# A preparation artifact must not contain private GPG working homes or temporary status text.
rm -rf /tmp/academy-gpg-debian /tmp/academy-gpg-pgdg
phase acquisition_complete
