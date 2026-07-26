#!/usr/bin/env bash
# install-tools.sh - Install external binaries required by the cybersquad pipeline.
#
# Targets Ubuntu/Debian (WSL). Run once before your first pipeline run.
# Safe to re-run - skips tools that are already on PATH.
#
# Tools installed:
#   Go (if absent or < 1.22): official tarball from go.dev
#   go install: subfinder, httpx, nuclei, ffuf, waybackurls, dnsx
#   apt         : nmap, sqlmap
#   git clone   : testssl.sh -> /usr/local/bin/testssl.sh

set -euo pipefail

GO_MIN_VERSION="1.22"
GO_INSTALL_VERSION="1.23.4"
BIN_DIR="${HOME}/.local/bin"
GOPATH="${GOPATH:-${HOME}/go}"
GOBIN="${GOPATH}/bin"

mkdir -p "${BIN_DIR}" "${GOBIN}"
export PATH="${BIN_DIR}:${GOBIN}:/usr/local/go/bin:${PATH}"

need() { command -v "$1" >/dev/null 2>&1; }

# ---- Go ----

install_go() {
  echo "[go]   Installing Go ${GO_INSTALL_VERSION} from go.dev..."
  local arch
  arch="$(uname -m)"
  case "${arch}" in
    x86_64)  arch="amd64" ;;
    aarch64) arch="arm64" ;;
    *) echo "Unsupported arch: ${arch}"; exit 1 ;;
  esac
  local tarball="go${GO_INSTALL_VERSION}.linux-${arch}.tar.gz"
  curl -fsSL "https://go.dev/dl/${tarball}" -o "/tmp/${tarball}"
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf "/tmp/${tarball}"
  rm "/tmp/${tarball}"
  echo "[ok]   Go $(go version)"
}

version_ge() {
  # Returns 0 if $1 >= $2 (semver, major.minor only)
  local a b
  a="$(echo "$1" | awk -F. '{printf "%05d%05d", $1, $2}')"
  b="$(echo "$2" | awk -F. '{printf "%05d%05d", $1, $2}')"
  [[ "${a}" -ge "${b}" ]]
}

echo ""
echo "==> Checking Go..."
if need go; then
  CURRENT_GO="$(go version | awk '{print $3}' | sed 's/go//')"
  if version_ge "${CURRENT_GO}" "${GO_MIN_VERSION}"; then
    echo "[skip] Go ${CURRENT_GO} already installed"
  else
    echo "[warn] Go ${CURRENT_GO} is below minimum ${GO_MIN_VERSION} - upgrading..."
    install_go
  fi
else
  install_go
fi

# ---- apt packages ----

echo ""
echo "==> Installing apt packages..."
sudo apt-get update -qq

for pkg in nmap sqlmap; do
  if need "${pkg}"; then
    echo "[skip] ${pkg} already installed"
  else
    echo "[apt]  Installing ${pkg}..."
    sudo apt-get install -y "${pkg}"
  fi
done

# ---- Go tools ----

echo ""
echo "==> Installing Go tools..."

declare -A GO_TOOLS=(
  [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
  [httpx]="github.com/projectdiscovery/httpx/cmd/httpx"
  [nuclei]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
  [ffuf]="github.com/ffuf/ffuf/v2@latest"
  [waybackurls]="github.com/tomnomnom/waybackurls"
  [dnsx]="github.com/projectdiscovery/dnsx/cmd/dnsx"
)

for tool in "${!GO_TOOLS[@]}"; do
  if [[ -x "${GOBIN}/${tool}" ]]; then
    echo "[skip] ${tool} already in ${GOBIN}"
    # Note: we check GOBIN specifically, not PATH, because a tool of the same
    # name can exist elsewhere (e.g. the Python httpx CLI in .venv/bin).
  else
    echo "[go]   go install ${GO_TOOLS[${tool}]}..."
    pkg="${GO_TOOLS[${tool}]}"
    # append @latest if not already versioned
    [[ "${pkg}" == *@* ]] || pkg="${pkg}@latest"
    GOPATH="${GOPATH}" go install "${pkg}"
    echo "[ok]   ${tool}"
  fi
done

# ---- testssl.sh ----

echo ""
echo "==> Checking testssl.sh..."
if need testssl.sh || need testssl; then
  echo "[skip] testssl.sh already on PATH"
else
  echo "[git]  Cloning testssl.sh..."
  TESTSSL_DIR="/opt/testssl"
  if [[ -d "${TESTSSL_DIR}" ]]; then
    (cd "${TESTSSL_DIR}" && sudo git pull -q)
  else
    sudo git clone --depth 1 https://github.com/drwetter/testssl.sh.git "${TESTSSL_DIR}"
  fi
  sudo ln -sf "${TESTSSL_DIR}/testssl.sh" /usr/local/bin/testssl.sh
  echo "[ok]   testssl.sh -> /usr/local/bin/testssl.sh"
fi

# ---- nuclei templates ----

echo ""
echo "==> Updating nuclei templates..."
TEMPLATES_DIR="${HOME}/.local/nuclei-templates"
nuclei -update-templates -update-template-dir "${TEMPLATES_DIR}" 2>/dev/null \
  && echo "[ok]   Templates at ${TEMPLATES_DIR}" \
  || echo "[warn] Template update failed - run manually: nuclei -update-templates"

# ---- PATH update ----

# shellcheck disable=SC2016  # single quotes intentional: ${HOME} must expand at source-time, not now
PATH_LINE='export PATH="${HOME}/.local/bin:${HOME}/go/bin:/usr/local/go/bin:${PATH}"'

for rc_file in "${HOME}/.bashrc" "${HOME}/.zshrc"; do
  if [[ -f "${rc_file}" ]] && ! grep -qF 'go/bin' "${rc_file}"; then
    { echo ""; echo "# Added by cybersquad install-tools.sh"; echo "${PATH_LINE}"; } >> "${rc_file}"
    echo "[ok]   Added PATH entry to ${rc_file}"
  elif [[ -f "${rc_file}" ]]; then
    echo "[skip] go/bin already in ${rc_file}"
  fi
done

echo ""
echo "==> PATH is updated. Run 'source ~/.bashrc' (or open a new terminal) to use new tools."

# ---- summary ----

echo ""
echo "==> Tool check:"
for tool in subfinder httpx dnsx nmap nuclei ffuf waybackurls sqlmap testssl.sh; do
  if need "${tool}"; then
    echo "  [ok]      ${tool} -> $(command -v ${tool})"
  else
    echo "  [MISSING] ${tool}"
  fi
done
