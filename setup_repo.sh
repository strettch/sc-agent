#!/bin/bash
set -e

# --- Configuration ---
ORG_NAME="strettch"
GPG_EMAIL="engineering@strettch.com"
PACKAGE_NAME="sc-metrics-agent"
PACKAGE_VERSION=$(git describe --tags --always --dirty) # Version is sourced from git tag
REPO_DOMAIN="repo.cloud.strettch.dev"
DISTRIBUTIONS="focal jammy noble" # Use spaces for loop iteration
# The standard, public-facing directory for the repository files.
# Using /var/www/html is the standard practice and avoids AppArmor/SELinux issues.
WEB_ROOT_DIR="/var/www/html/aptly"
# ---

# --- Asset Paths (uses files from your repo) ---
SERVICE_FILE="packaging/systemd/${PACKAGE_NAME}.service"
POSTINSTALL_SCRIPT="packaging/scripts/post-install.sh"
PREREMOVE_SCRIPT="packaging/scripts/pre-remove.sh"
START_SCRIPT_FILENAME="sc-agent.sh"
START_SCRIPT_SOURCE_PATH="packaging/scripts/${START_SCRIPT_FILENAME}"
# ---

# --- Pre-flight Checks ---
if [ ! -f "$SERVICE_FILE" ]; then
    echo "Error: Service file not found at ${SERVICE_FILE}" >&2
    exit 1
fi
if [ ! -f "$POSTINSTALL_SCRIPT" ]; then
    echo "Error: Post-install script not found at ${POSTINSTALL_SCRIPT}" >&2
    exit 1
fi
if [ ! -f "$PREREMOVE_SCRIPT" ]; then
    echo "Error: Pre-remove script not found at ${PREREMOVE_SCRIPT}" >&2
    exit 1
fi
if [ ! -f "$START_SCRIPT_SOURCE_PATH" ]; then
    echo "Error: Start script not found at ${START_SCRIPT_SOURCE_PATH}" >&2
    exit 1
fi
# ---

echo "--- [Step 1/7] Cleaning up previous repository publications..."
for dist in ${DISTRIBUTIONS}; do
    sudo aptly publish drop ${dist} || echo "No repository for '${dist}' was published. Continuing."
done
sudo aptly publish drop "focal,jammy,noble" || echo "No malformed composite repository found. Continuing."

if sudo aptly snapshot list -raw | grep -q .; then
    echo "Deleting existing snapshots..."
    while IFS= read -r snapshot_name; do
        if [ -n "$snapshot_name" ]; then
            echo " - Dropping snapshot: $snapshot_name"
            sudo aptly snapshot drop "$snapshot_name"
        fi
    done <<< "$(sudo aptly snapshot list -raw)"
fi
sudo aptly db cleanup
sudo aptly repo remove sc-metrics-agent-repo ${PACKAGE_NAME} || echo "No package to remove from repo. Continuing."
rm -f ${PACKAGE_NAME}_*.deb

echo "--- [Step 2/7] Building Go binary via Makefile..."
make GOOS=linux GOARCH=amd64 build

echo "--- [Step 3/7] Preparing packaging assets..."
STAGING_DIR="/tmp/${PACKAGE_NAME}-build"
rm -rf "${STAGING_DIR}"
mkdir -p "${STAGING_DIR}/usr/local/bin" "${STAGING_DIR}/etc/${PACKAGE_NAME}" "${STAGING_DIR}/etc/systemd/system"
cp build/${PACKAGE_NAME} "${STAGING_DIR}/usr/local/bin/"
# === Add start script ===
cp "${START_SCRIPT_SOURCE_PATH}" "${STAGING_DIR}/usr/local/bin/${START_SCRIPT_FILENAME}"
chmod +x "${STAGING_DIR}/usr/local/bin/${START_SCRIPT_FILENAME}"
# === End add start script ===
cp config.example.yaml "${STAGING_DIR}/etc/${PACKAGE_NAME}/config.yaml"
cp "${SERVICE_FILE}" "${STAGING_DIR}/etc/systemd/system/"
chmod +x "${POSTINSTALL_SCRIPT}" "${PREREMOVE_SCRIPT}"

echo "--- [Step 4/7] Building the .deb package..."
fpm -s dir -t deb -n ${PACKAGE_NAME} -v ${PACKAGE_VERSION} \
  -C "${STAGING_DIR}/" \
  --description "SC Metrics Agent for system monitoring by ${ORG_NAME}" \
  --maintainer "${GPG_EMAIL}" \
  --url "https://github.com/strettch/sc-metrics-agent" \
  --depends "libc6" --depends "dmidecode" \
  --after-install "${POSTINSTALL_SCRIPT}" \
  --before-remove "${PREREMOVE_SCRIPT}"

echo "--- [Step 5/7] Creating and Publishing the new version..."
if ! sudo aptly repo show sc-metrics-agent-repo > /dev/null 2>&1; then
    FIRST_DIST=$(echo ${DISTRIBUTIONS} | cut -d' ' -f1)
    sudo aptly repo create -distribution="${FIRST_DIST}" -component="main" sc-metrics-agent-repo
fi
sudo aptly repo add sc-metrics-agent-repo ${PACKAGE_NAME}_${PACKAGE_VERSION#v}_amd64.deb
SNAPSHOT_NAME="${PACKAGE_NAME}-${PACKAGE_VERSION}"
sudo aptly snapshot create "${SNAPSHOT_NAME}" from repo sc-metrics-agent-repo

echo "Publishing new snapshot to distributions: ${DISTRIBUTIONS}"
for dist in ${DISTRIBUTIONS}; do
    sudo aptly publish snapshot -gpg-key="${GPG_EMAIL}" -distribution="${dist}" "${SNAPSHOT_NAME}"
done

echo "--- [Step 6/7] Configuring web server and generating client install script..."
sudo mkdir -p "${WEB_ROOT_DIR}"
sudo rsync -a --delete /root/.aptly/public/ "${WEB_ROOT_DIR}/"

GPG_PUBLIC_KEY_FILE="${PACKAGE_NAME}-repo.gpg"
gpg --armor --export "${GPG_EMAIL}" > "${GPG_PUBLIC_KEY_FILE}"
sudo mv "${GPG_PUBLIC_KEY_FILE}" "${WEB_ROOT_DIR}/"

INSTALL_SCRIPT_PATH="${WEB_ROOT_DIR}/install.sh"
TMP_INSTALL_SCRIPT=$(mktemp)
cat << EOF > "${TMP_INSTALL_SCRIPT}"
#!/bin/sh
set -e
# --- Configuration ---
REPO_HOST="${REPO_DOMAIN}"
PACKAGE_NAME="${PACKAGE_NAME}"
GPG_KEY_FILENAME="${GPG_PUBLIC_KEY_FILE}"
CONFIG_FILE="/etc/${PACKAGE_NAME}/config.yaml"
# ---
if [ "\$(id -u)" -ne "0" ]; then
    echo "This script must be run as root. Please use 'sudo'." >&2
    exit 1
fi
if [ -f /etc/os-release ]; then
    DISTRIBUTION=\$(. /etc/os-release && echo "\$VERSION_CODENAME")
else
    echo "Error: Unable to detect OS distribution codename." >&2
    exit 1
fi
echo "--- Installing \${PACKAGE_NAME} for \${DISTRIBUTION} ---"

log_and_run() {
    echo "\$1"
    if ! eval "\$2"; then
        echo "Error: Failed to \$3. Please check the output above for details." >&2
        exit 1
    fi
}

log_and_run "Updating package lists..." "apt-get update > /dev/null" "update package lists"
log_and_run "Installing prerequisite packages..." "apt-get install -y apt-transport-https ca-certificates curl gnupg > /dev/null" "install prerequisite packages"

KEYRING_FILE="/usr/share/keyrings/\${PACKAGE_NAME}-keyring.gpg"
log_and_run "Downloading and installing GPG key..." "curl -fsSL \"https://\${REPO_HOST}/\${GPG_KEY_FILENAME}\" | gpg --dearmor | sudo tee \"\${KEYRING_FILE}\" >/dev/null" "download and install GPG key"

SOURCES_FILE="/etc/apt/sources.list.d/\${PACKAGE_NAME}.list"
log_and_run "Adding \${PACKAGE_NAME} repository..." "echo \"deb [signed-by=\${KEYRING_FILE}] https://\${REPO_HOST} \${DISTRIBUTION} main\" | sudo tee \"\${SOURCES_FILE}\" >/dev/null" "add \${PACKAGE_NAME} repository"

log_and_run "Updating package list for \${PACKAGE_NAME}..." "apt-get update -o Dir::Etc::SourceList='\${SOURCES_FILE}' -o Dir::Etc::SourceParts='-' -o APT::Get::List-Cleanup='0' > /dev/null" "update package list for \${PACKAGE_NAME}"

log_and_run "Installing \${PACKAGE_NAME}..." "apt-get install -y \"\${PACKAGE_NAME}\"" "install \${PACKAGE_NAME}"
echo
echo "---"
echo "✅ \${PACKAGE_NAME} was installed successfully!"
echo "IMPORTANT: Please edit the configuration file to set your ingestor endpoint:"
echo "   sudo nano \${CONFIG_FILE}"
echo "After editing, restart the agent: sudo systemctl restart \${PACKAGE_NAME}"
echo "To check status: systemctl status \${PACKAGE_NAME}"
echo "---"
exit 0
EOF

sudo mv "${TMP_INSTALL_SCRIPT}" "${INSTALL_SCRIPT_PATH}"

echo "--- [Step 7/7] Finalizing permissions and restarting Caddy..."
# This is the crucial fix: set ownership and permissions AFTER all files are in place.
sudo chmod 755 /var/www /var/www/html
sudo chown -R caddy:caddy "${WEB_ROOT_DIR}"
sudo chmod -R 755 "${WEB_ROOT_DIR}"

sudo bash -c "cat << EOF > /etc/caddy/Caddyfile
${REPO_DOMAIN} {
    root * ${WEB_ROOT_DIR}
    file_server
}
EOF"
sudo systemctl restart caddy

echo
echo "========================================================================"
echo "✅ Repository setup complete!"
echo "To install the agent on a client machine, run:"
echo "curl -sSL https://${REPO_DOMAIN}/install.sh | sudo bash"
echo "========================================================================"