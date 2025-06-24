#!/bin/bash

# Script to replace ArrayConverter with DataConverter

echo "Starting ArrayConverter to DataConverter replacement..."

# Find all Java files containing ArrayConverter (excluding target directory)
FILES=$(find . -name "*.java" -type f | xargs grep -l "ArrayConverter" | grep -v target)

if [ -z "$FILES" ]; then
    echo "No files found containing ArrayConverter"
    exit 0
fi

echo "Found files to process:"
echo "$FILES"
echo ""

# Process each file
for file in $FILES; do
    echo "Processing: $file"
    
    # Create backup
    cp "$file" "$file.bak"
    
    # Replace import statement
    sed -i 's/import de\.rub\.nds\.modifiablevariable\.util\.ArrayConverter;/import de.rub.nds.modifiablevariable.util.DataConverter;/g' "$file"
    
    # Replace all ArrayConverter. with DataConverter.
    sed -i 's/ArrayConverter\./DataConverter./g' "$file"
    
    # Show changes
    if diff -q "$file.bak" "$file" >/dev/null; then
        echo "  No changes made"
        rm "$file.bak"
    else
        echo "  Changes made:"
        diff -u "$file.bak" "$file" | grep "^[+-]" | grep -v "^[+-]\{3\}" | head -10
        rm "$file.bak"
    fi
    echo ""
done

echo "Replacement complete!"
echo ""
echo "Summary of changes:"
echo "==================="
git diff --stat