#! /bin/bash
set -eu
./change-scala-versions.sh 2.11 # default
mvn "$@"
./change-scala-versions.sh 2.10
mvn "$@"
./change-scala-versions.sh 2.11 # back to default
