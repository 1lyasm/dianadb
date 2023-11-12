#!/usr/bin/bash

cd ..
make
git add -f target/debug/diserver
git commit -m "Update binary"
git push

cd ../dianadb_app
cargo update
make
git add -f target/debug/dianadb_app
git add Cargo.lock
git commit -m "Update binary"
git push
