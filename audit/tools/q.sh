#!/bin/sh
# q.sh <name> <logdir> -- run commands read from stdin one after another, each with its own log
# and a status line in <logdir>/<name>.status:  <label> exit=<n> secs=<n>
name=$1; logdir=$2
: > "$logdir/$name.status"
while IFS='|' read -r label cmd; do
  [ -z "$label" ] && continue
  start=$(date +%s)
  echo "RUNNING $label $(date -u +%T)" >> "$logdir/$name.status"
  sh -c "$cmd" > "$logdir/$label.log" 2>&1
  rc=$?
  end=$(date +%s)
  sed -i "\$d" "$logdir/$name.status"
  echo "$label exit=$rc secs=$((end-start))" >> "$logdir/$name.status"
done
echo "QUEUE-DONE $(date -u +%T)" >> "$logdir/$name.status"
