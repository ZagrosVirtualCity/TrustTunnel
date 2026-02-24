#!/bin/bash

set -e

MANIFEST_FILE=$1

increment_version() {
  major=${1%%.*}
  minor=$(echo ${1#*.} | sed -e "s/\.[0-9]*//")
  revision=${1##*.}
  echo ${major}.${minor}.$((revision+1))
}

VERSION=$(grep "version = " "$MANIFEST_FILE" | head -n 1 | sed -e 's/version = "\(.*\)"/\1/')

argument_version=$2
if [ -z "$argument_version" ]
then
  NEW_VERSION=$(increment_version ${VERSION})
else
  NEW_VERSION=$argument_version
fi

if ! [[ "${NEW_VERSION}" =~ ^[0-9]\.[0-9]\.[0-9]*$ ]]
then
  echo "New version is invalid: ${NEW_VERSION}"
  exit 1
fi

echo "Last version was ${VERSION}"
echo "New version is ${NEW_VERSION}"

set -x

# Update toml
sed -i -e "s/^version = \"${VERSION}\"$/version = \"${NEW_VERSION}\"/" "$MANIFEST_FILE"

# Update changelog
sed -i -e "3{
/##/b
s/^/## ${NEW_VERSION}\n\n/
}" CHANGELOG.md

# Update Cargo.lock
python3 -c "
with open('Cargo.lock', 'r', encoding='UTF-8') as file:
    content = file.read()

output = ''
is_in_trusttunnel_endpoint_section = False
for line in content.splitlines():
    if line == 'name = \"trusttunnel_endpoint\"':
        is_in_trusttunnel_endpoint_section = True
    elif is_in_trusttunnel_endpoint_section:
        is_in_trusttunnel_endpoint_section = line != '[[package]]'

    if is_in_trusttunnel_endpoint_section and line == 'version = \"${VERSION}\"':
        output += 'version = \"${NEW_VERSION}\"\n'
        continue

    output += line + '\n'

with open('Cargo.lock', 'w') as file:
    file.write(output)
"
