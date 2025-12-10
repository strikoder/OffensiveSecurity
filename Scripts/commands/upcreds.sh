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

# Function to check if string contains special characters that need quoting
needs_quotes() {
    local str="$1"
    # Check for spaces, special shell characters, or anything non-alphanumeric except - _ . /
    if [[ "$str" =~ [^a-zA-Z0-9._/-] ]]; then
        return 0  # needs quotes
    else
        return 1  # doesn't need quotes
    fi
}

counter=1
while IFS= read -r line || [ -n "$line" ]; do
    # Skip empty lines
    [ -z "$line" ] && continue
    
    if [[ "$line" == :* ]]; then
        # Line starts with : - password only
        password="${line#:}"
        if needs_quotes "$password"; then
            exportall "pass${counter}='${password}'"
        else
            exportall "pass${counter}=${password}"
        fi
        echo "Exported: pass${counter}"
        ((counter++))
    elif [[ "$line" == *:* ]]; then
        # Line contains : - username:password
        username="${line%%:*}"
        password="${line#*:}"
        
        if needs_quotes "$username"; then
            exportall "user${counter}='${username}'"
        else
            exportall "user${counter}=${username}"
        fi
        
        if needs_quotes "$password"; then
            exportall "pass${counter}='${password}'"
        else
            exportall "pass${counter}=${password}"
        fi
        
        echo "Exported: user${counter}, pass${counter}"
        ((counter++))
    else
        # Line has no : - username only
        username="$line"
        if needs_quotes "$username"; then
            exportall "user${counter}='${username}'"
        else
            exportall "user${counter}=${username}"
        fi
        echo "Exported: user${counter}"
        ((counter++))
    fi
done < "$FILE"
echo "Total entries processed: $((counter - 1))"
