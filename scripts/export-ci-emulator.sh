#!/bin/sh
# The release image uses musl. Copy its exact kkemu runtime so the offline
# Ubuntu test worker can start and restart it without access to Docker.
set -eu
container=$1
dest=$2
mkdir -p "$dest/lib"
docker cp -L "$container:/kkemu/bin/kkemu" "$dest/kkemu.bin"
docker cp -L "$container:/lib/ld-musl-x86_64.so.1" "$dest/ld-musl"
for library in libstdc++.so.6 libgcc_s.so.1; do
    docker cp -L "$container:/usr/lib/$library" "$dest/lib/$library"
done
cat > "$dest/kkemu" <<'LAUNCHER'
#!/bin/sh
dir=$(dirname "$0")
exec "$dir/ld-musl" --library-path "$dir/lib" "$dir/kkemu.bin" "$@"
LAUNCHER
chmod +x "$dest/kkemu"
test -x "$dest/ld-musl"
test -x "$dest/kkemu.bin"
