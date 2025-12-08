#!/bin/bash

# Usage: source ./script.sh <filename>
# OR: . ./script.sh <filename>

if [ $# -eq 0 ]; then
    echo "Usage: $0 <filename>"
    exit 1
fi

FILE="$1"

if [ ! -f "$FILE" ]; then
    echo "Error: File '$FILE' not found"
    exit 1
fi

counter=1

while IFS= read -r line || [ -n "$line" ]; do
    # Skip empty lines
    [ -z "$line" ] && continue
    
    if [[ "$line" == :* ]]; then
        # Line starts with : - password only
        password="${line#:}"
        exportall "pass${counter}='${password}'"
        echo "Exported: pass${counter}"
        ((counter++))
    elif [[ "$line" == *:* ]]; then
        # Line contains : - username:password
        username="${line%%:*}"
        password="${line#*:}"
        exportall "user${counter}=${username}"
        exportall "pass${counter}='${password}'"
        echo "Exported: user${counter}, pass${counter}"
        ((counter++))
    else
        # Line has no : - username only
        username="$line"
        exportall "user${counter}=${username}"
        echo "Exported: user${counter}"
        ((counter++))
    fi
done < "$FILE"

echo "Total entries processed: $((counter - 1))"
