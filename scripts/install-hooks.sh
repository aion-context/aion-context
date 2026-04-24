#!/bin/bash
# Install git hooks for AION v2 development
# Run this script to set up pre-commit hooks: ./scripts/install-hooks.sh

set -e

HOOKS_DIR=".git/hooks"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🔧 Installing git hooks for AION v2..."

# Create pre-commit hook
cat > "$HOOKS_DIR/pre-commit" << 'EOF'
#!/bin/bash
# Pre-commit hook for AION v2
# Automatically formats Rust code before commit

set -e

echo "🔍 Running pre-commit checks..."

# Check if there are any staged Rust files
RUST_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.rs$' || true)

if [ -n "$RUST_FILES" ]; then
    echo "📝 Formatting Rust code..."
    cargo fmt
    
    # Add the formatted files back to staging
    git add $RUST_FILES
    
    echo "✅ Code formatted successfully"
else
    echo "ℹ️  No Rust files to format"
fi

echo "✨ Pre-commit checks complete!"
EOF

# Make hooks executable
chmod +x "$HOOKS_DIR/pre-commit"

echo "✅ Git hooks installed successfully!"
echo ""
echo "The following hooks are now active:"
echo "  - pre-commit: Automatically formats Rust code"
echo ""
echo "To skip hooks temporarily, use: git commit --no-verify"
