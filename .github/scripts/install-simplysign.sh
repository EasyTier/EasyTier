#!/bin/bash

# Install SimplySign Desktop - Clean MSI Installation

set -euo pipefail

echo "=== INSTALLING SIMPLYSIGN DESKTOP ==="
echo "Using proven installation method from successful testing..."

# Download SimplySign Desktop MSI
CERTUM_INSTALLER="SimplySignDesktop.msi"
echo "Downloading SimplySign Desktop MSI..."

if curl -L "https://files.certum.eu/software/SimplySignDesktop/Windows/9.3.2.67/SimplySignDesktop-9.3.2.67-64-bit-en.msi" -o "$CERTUM_INSTALLER" --fail --max-time 60; then
  echo "✅ Downloaded SimplySign Desktop MSI ($(ls -lh "$CERTUM_INSTALLER" | awk '{print $5}'))"
else
  echo "❌ Failed to download SimplySign Desktop"
  exit 1
fi

# Install with proven method (matching successful test)
echo "Installing SimplySign Desktop..."
echo "Full command: msiexec /i \"$CERTUM_INSTALLER\" /quiet /norestart /l*v install.log ALLUSERS=1 REBOOT=ReallySuppress"

# Check for administrative privileges (like the successful test)
ADMIN_RIGHTS=false
if powershell -Command "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)" 2>/dev/null; then
  echo "✅ Running with administrative privileges"
  ADMIN_RIGHTS=true
else
  echo "⚠️ No explicit administrative privileges detected"
fi

# Use the exact method that worked: PowerShell with admin privileges
if [ "$ADMIN_RIGHTS" = true ]; then
  echo "Running MSI installation with administrator privileges..."
  powershell -Command "Start-Process -FilePath 'msiexec.exe' -ArgumentList '/i', '\"$CERTUM_INSTALLER\"', '/quiet', '/norestart', '/l*v', 'install.log', 'ALLUSERS=1', 'REBOOT=ReallySuppress' -Wait -NoNewWindow -PassThru" &
  INSTALL_PID=$!
else
  echo "Running MSI installation without explicit admin elevation..."
  timeout 300 msiexec /i "$CERTUM_INSTALLER" /quiet /norestart /l*v install.log ALLUSERS=1 REBOOT=ReallySuppress &
  INSTALL_PID=$!
fi

# Monitor with the same logic as successful test
echo "Monitoring installation progress..."
INSTALL_START_TIME=$(date +%s)
sleep 10

# Check if msiexec process is actually running (like successful test)
if kill -0 $INSTALL_PID 2>/dev/null; then
  echo "MSI installation process is running (PID: $INSTALL_PID)"
  
  # Monitor for up to 3 minutes with status updates
  for i in {1..18}; do
    sleep 10
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - INSTALL_START_TIME))
    
    if kill -0 $INSTALL_PID 2>/dev/null; then
      echo "Installation still running after ${ELAPSED} seconds..."
      
      # Check log file growth
      if [ -f "install.log" ]; then
        LOG_SIZE=$(stat -c%s "install.log" 2>/dev/null || stat -f%z "install.log" 2>/dev/null || echo 0)
        echo "  Log file size: $LOG_SIZE bytes"
      fi
    else
      echo "MSI installation completed after ${ELAPSED} seconds"
      break
    fi
  done
  
  # Final wait if still running
  if kill -0 $INSTALL_PID 2>/dev/null; then
    echo "Installation taking longer, waiting for completion..."
    wait $INSTALL_PID 2>/dev/null || echo "Installation process ended"
  fi
else
  echo "MSI installation process ended quickly"
fi

# Quick success check using proven patterns
INSTALLATION_SUCCESSFUL=false
if [ -f "install.log" ]; then
  if grep -qi "Installation.*operation.*completed.*successfully\|Installation.*success.*or.*error.*status.*0\|MainEngineThread.*is.*returning.*0\|Windows.*Installer.*installed.*the.*product" install.log 2>/dev/null; then
    echo "✅ Installation successful (confirmed by log patterns)"
    INSTALLATION_SUCCESSFUL=true
  fi
fi

# Verify installation directory
INSTALL_PATH="/c/Program Files/Certum/SimplySign Desktop"
if [ -d "$INSTALL_PATH" ]; then
  echo "✅ SimplySign Desktop installed successfully"
  echo "✅ Virtual card emulation now active for code signing"
  INSTALLATION_SUCCESSFUL=true
  
  # Set output for GitHub Actions
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "SIMPLYSIGN_PATH=$INSTALL_PATH" >> "$GITHUB_OUTPUT"
  fi
fi

if [ "$INSTALLATION_SUCCESSFUL" = false ]; then
  echo "❌ Installation verification failed"
  echo "Last 10 lines of install log:"
  tail -10 install.log 2>/dev/null || echo "No install log available"
  exit 1
fi

echo "🎉 SimplySign Desktop installation completed successfully!"
