#!/bin/bash
# setup.sh - Quick setup for JS Monitoring System

echo "🚀 Setting up JavaScript Monitoring System..."

# Check if Python3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found. Please install Python3."
    exit 1
fi

# Install dependencies
echo "📦 Installing Python dependencies..."
pip3 install selenium requests beautifulsoup4 urllib3 --break-system-packages

# Update geckodriver
echo "🔧 Updating geckodriver..."
wget -q https://github.com/mozilla/geckodriver/releases/download/v0.36.0/geckodriver-v0.36.0-linux64.tar.gz
tar -xvzf geckodriver-v0.36.0-linux64.tar.gz
sudo mv geckodriver /usr/local/bin/
sudo chmod +x /usr/local/bin/geckodriver
rm geckodriver-v0.36.0-linux64.tar.gz

# Create example files
echo "📝 Creating example configuration..."
cat > targets.txt << 'EOF'
# Add your target URLs here (one per line)
https://example.com
https://www.google.com
EOF

cat > quick_run.sh << 'EOF'
#!/bin/bash
echo "🚀 Running JavaScript Monitoring System..."
python3 js_monitoring_system.py gather -t targets.txt --concurrent 2
EOF

chmod +x quick_run.sh

echo "✅ Setup complete!"
echo ""
echo "📋 Next steps:"
echo "1. Edit 'targets.txt' with your target URLs"
echo "2. Run: ./quick_run.sh"
echo "3. Or manually: python3 js_monitoring_system.py gather -t targets.txt"
echo ""
echo "📁 Output will be saved to 'monitor_output/' directory"
