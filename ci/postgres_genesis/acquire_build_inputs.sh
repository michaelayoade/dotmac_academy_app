#!/bin/bash
# Hosted disposable container only. No source build command is permitted here.
set -euo pipefail
umask 022
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=UTC DEBIAN_FRONTEND=noninteractive

phase() { printf '%s\n' "$1" > /out/phase.txt; }
diagnostic_count=0
diagnostic() {
    if [ "$diagnostic_count" -lt 512 ]; then
        printf '%s\t%s\n' "$1" "$2" >> /out/configuration-diagnostics.tsv
        diagnostic_count=$((diagnostic_count + 1))
    fi
}
file_kind() {
    if [ -L "$1" ]; then diagnostic file_kind symlink;
    elif [ -f "$1" ]; then diagnostic file_kind regular;
    elif [ -d "$1" ]; then diagnostic file_kind directory;
    elif [ -e "$1" ]; then diagnostic file_kind other;
    else diagnostic file_kind missing; fi
}
source_rejection() {
    # Only describe the first line rejected by the unchanged validation grammar.
    awk '
      /^[[:space:]]*(#|$)/ {next}
      /^Types: deb( deb-src)?$/ {next}
      /^URIs: https?:\/\/deb.debian.org\/debian(-security)?\/?$/ {next}
      /^Suites: trixie( trixie-updates)?$/ {next}
      /^Suites: trixie-security$/ {next}
      /^Components: main$/ {next}
      /^Signed-By: \/usr\/share\/keyrings\/debian-archive-keyring.gpg$/ {next}
      /^deb(-src)? \[[[:space:]]*signed-by=\/usr\/local\/share\/keyrings\/postgres.gpg.asc[[:space:]]*\] http:\/\/apt.postgresql.org\/pub\/repos\/apt\/? trixie-pgdg main( 16)?$/ {next}
      {
        field="other"
        if ($0 ~ /^[[:space:]]*Types:/) field="types"
        else if ($0 ~ /^[[:space:]]*URIs:/) field="uris"
        else if ($0 ~ /^[[:space:]]*Suites:/) field="suites"
        else if ($0 ~ /^[[:space:]]*Components:/) field="components"
        else if ($0 ~ /^[[:space:]]*Signed-By:/) field="signed_by"
        else if ($0 ~ /^[[:space:]]*Architectures:/) field="architectures"
        else if ($0 ~ /^[[:space:]]*Enabled:/) field="enabled"
        else if ($0 ~ /^[[:space:]]*deb(-src)?[[:space:]]/) field="deb_line"
        printf "source_rejected_field\t%s\n",field
        printf "known_uri_match\t%s\n",($0 ~ /https?:\/\/deb.debian.org\/debian(-security)?\/?([[:space:]]|$)/ || $0 ~ /http:\/\/apt.postgresql.org\/pub\/repos\/apt\/?([[:space:]]|$)/)?"true":"false"
        printf "known_suite_match\t%s\n",($0 ~ /(^|[[:space:]])trixie(-updates|-security|-pgdg)?([[:space:]]|$)/)?"true":"false"
        printf "known_signed_by_match\t%s\n",($0 ~ /\/usr\/share\/keyrings\/debian-archive-keyring.gpg/ || $0 ~ /\/usr\/local\/share\/keyrings\/postgres.gpg.asc/)?"true":"false"
        printf "leading_whitespace\t%s\n",($0 ~ /^[[:space:]]/)?"true":"false"
        printf "trailing_whitespace\t%s\n",($0 ~ /[[:space:]]$/)?"true":"false"
        printf "carriage_return\t%s\n",($0 ~ /\r/)?"true":"false"
        exit
      }
    ' "$1" >> /out/configuration-diagnostics.tsv
}
import_status_diagnostics() {
    # GPG arguments/UIDs/fingerprints never escape this private status parser.
    awk '
      function number(name,value) {
        if (value ~ /^[0-9]+$/ && length(value)<=10 && value+0<=4294967295)
          printf "%s\t%.0f\n",name,value+0
      }
      function operation(name,value) {
        if (value=="import" || value=="import_keys" || value=="keydb_search" || value=="keydb_get_keyblock" || value=="keydb_new" || value=="add_keyblock_resource" || value=="keybox_open")
          printf "%s\t%s\n",name,value
        else printf "%s\tother\n",name
      }
      $1=="[GNUPG:]" && ($2=="IMPORT_OK" || $2=="IMPORT_RES" || $2=="IMPORT_PROBLEM" || $2=="NODATA" || $2=="FAILURE" || $2=="ERROR") && count++<32 {
        printf "gpg_status_token\t%s\n",$2
        if ($2=="IMPORT_PROBLEM") number("gpg_import_problem_reason",$3)
        if ($2=="NODATA") number("gpg_nodata_reason",$3)
        if ($2=="FAILURE") {operation("gpg_failure_operation",$3);number("gpg_failure_code",$4)}
        if ($2=="ERROR") {operation("gpg_error_operation",$3);number("gpg_error_code",$4)}
      }
    ' "$1" >> /out/configuration-diagnostics.tsv
}
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
: > /out/configuration-diagnostics.tsv
# Only known public source configuration is copied; no auth.conf, environment or host keyring.
shopt -s nullglob
source_files=(/etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources)
for file in "${source_files[@]}"; do
    test -e "$file" || continue
    phase inherited_source_kind
    case "$file" in
      */sources.list) diagnostic source_file_class sources_list ;;
      */debian.sources) diagnostic source_file_class debian_sources ;;
      */pgdg.list) diagnostic source_file_class pgdg_list ;;
      *.sources) diagnostic source_file_class other_sources ;;
      *) diagnostic source_file_class other_list ;;
    esac
    file_kind "$file"
    test -f "$file" && test ! -L "$file"
    phase inherited_source_copy
    cp "$file" "/out/apt/inherited/$(basename "$file")"
    phase inherited_source_validation
    if awk '
      /^[[:space:]]*(#|$)/ {next}
      /^Types: deb( deb-src)?$/ {next}
      /^URIs: https?:\/\/deb.debian.org\/debian(-security)?\/?$/ {next}
      /^Suites: trixie( trixie-updates)?$/ {next}
      /^Suites: trixie-security$/ {next}
      /^Components: main$/ {next}
      /^Signed-By: \/usr\/share\/keyrings\/debian-archive-keyring.gpg$/ {next}
      /^deb(-src)? \[[[:space:]]*signed-by=\/usr\/local\/share\/keyrings\/postgres.gpg.asc[[:space:]]*\] http:\/\/apt.postgresql.org\/pub\/repos\/apt\/? trixie-pgdg main( 16)?$/ {next}
      {exit 1}
    ' "$file"; then
        diagnostic source_validation success
    else
        code=$?
        diagnostic source_validation failure
        source_rejection "$file"
        exit "$code"
    fi
done
for file in /etc/apt/apt.conf.d/*; do
    phase inherited_hook_kind
    case "$file" in
      */docker-clean) diagnostic hook_file_class docker_clean ;;
      */docker-gzip-indexes) diagnostic hook_file_class docker_gzip_indexes ;;
      */docker-no-languages) diagnostic hook_file_class docker_no_languages ;;
      */docker-autoremove-suggests) diagnostic hook_file_class docker_autoremove_suggests ;;
      */70debconf) diagnostic hook_file_class debconf ;;
      *) diagnostic hook_file_class other ;;
    esac
    file_kind "$file"
    test -f "$file" && test ! -L "$file"
    phase inherited_hook_validation
    # A hook targeting our custom cache must be reviewed, never silently disabled.
    if grep -Eq '/out|[Aa]llow[Uu]nauthenticated|[Aa]llow[Ii]nsecure|[Cc]heck-[Vv]alid-[Uu]ntil.*false' "$file"; then
        diagnostic hook_validation failure
        awk '
          /\/out/ {print "hook_rejection\tcustom_cache_reference";exit}
          /[Aa]llow[Uu]nauthenticated/ {print "hook_rejection\tunauthenticated_option_token";exit}
          /[Aa]llow[Ii]nsecure/ {print "hook_rejection\tinsecure_option_token";exit}
          /[Cc]heck-[Vv]alid-[Uu]ntil.*false/ {print "hook_rejection\tvalid_until_false_token";exit}
        ' "$file" >> /out/configuration-diagnostics.tsv
        exit 1
    fi
    diagnostic hook_validation success
    phase inherited_hook_copy
    cp "$file" "/out/apt/inherited/config-$(basename "$file")"
done
phase debian_keyring_copy
cp /usr/share/keyrings/debian-archive-keyring.gpg /out/apt/keys/debian-archive-keyring.gpg
phase pgdg_keyring_copy
cp /usr/local/share/keyrings/postgres.gpg.asc /out/apt/keys/postgres.gpg.asc
phase explicit_config_creation
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
phase explicit_config_capture
cp /tmp/academy-apt.conf /out/apt/academy-apt.conf
cp /tmp/academy-sources.list /out/apt/academy-sources.list
for key in debian pgdg; do
    diagnostic key_context "$key"
    phase "${key}_key_home"
    home="/tmp/academy-gpg-$key"
    mkdir -m 0700 "$home"
    if [ "$key" = debian ]; then public=/out/apt/keys/debian-archive-keyring.gpg;
    else public=/out/apt/keys/postgres.gpg.asc; fi
    awk 'NR==1 {if($0=="-----BEGIN PGP PUBLIC KEY BLOCK-----")print "key_format\tarmored_public_key";else print "key_format\tbinary_or_other";exit}' "$public" >> /out/configuration-diagnostics.tsv
    phase "${key}_key_import"
    code=0
    gpg --no-options --homedir "$home" --batch --no-auto-key-retrieve --no-autostart --auto-key-locate clear --status-fd 1 --import "$public" > "$home/import-status" 2>/dev/null || code=$?
    diagnostic import_exit_code "$code"
    if [ "$code" -eq 0 ]; then diagnostic import_outcome success; else diagnostic import_outcome nonzero; fi
    import_status_diagnostics "$home/import-status"
    if [ "$code" -ne 0 ]; then exit "$code"; fi
    phase "${key}_fingerprint_listing"
    if gpg --no-options --homedir "$home" --batch --no-autostart --with-colons --fingerprint --list-keys 2>/dev/null |
        awk -F: '$1=="pub"{primary=1;next} $1=="sub"{primary=0} $1=="fpr" && primary{print $10;primary=0}' > "/out/apt/keys/$key-primary-fingerprints.txt"; then
        diagnostic fingerprint_list_outcome success
    else
        code=$?
        diagnostic fingerprint_list_outcome nonzero
        diagnostic fingerprint_list_exit_code "$code"
        exit "$code"
    fi
    phase "${key}_fingerprint_nonempty"
    awk 'END{printf "primary_count\t%.0f\n",NR>64?64:NR;printf "primary_count_capped\t%s\n",NR>64?"true":"false"}' "/out/apt/keys/$key-primary-fingerprints.txt" >> /out/configuration-diagnostics.tsv
    test -s "/out/apt/keys/$key-primary-fingerprints.txt"
done
phase pgdg_fingerprint_match
awk '{if($0=="B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8")matched++;else other++}END{printf "pinned_fingerprint_match\t%s\n",matched==1&&!other?"true":"false"}' /out/apt/keys/pgdg-primary-fingerprints.txt >> /out/configuration-diagnostics.tsv
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
