"""Fixed in-container shell programs.

Agent text reaches them only as positional parameters ("$1", "$2"), never by string
formatting.
"""
from __future__ import annotations

# bash; $1 = timeout seconds (integer), $2 = command text.
#
# The command runs in its own session (so its whole process group can be killed) with stdin
# from /dev/null. A watcher in a separate session kills that group after $1 seconds; its
# output goes to /dev/null so it never holds the exec's pipes. When the command ends, both
# the command's group and the watcher's group are killed (group and pid each, errors ignored;
# anything that escaped is reaped by REAP_SCRIPT after every run_command).
#
# Decision rule for the exit status (it must NOT depend on whether the watcher survived to
# its own `exit 0`, because the wrapper kills the watcher right after the command ends and
# that kill can land before or after the watcher's `exit 0`):
#   exit 124  iff  wrc == 0                                  (watcher ran to completion)
#             or   (rc == 137 and elapsed >= $1 * 100 - 50 centiseconds)
#   otherwise the command's own status.
# Elapsed time comes from /proc/uptime, read with bash builtins only (no fork), taken before
# the command is launched and again right after `wait` returns, before any kill is sent.
# A SIGKILL (137) that arrives about $1 seconds in is the watcher's doing; a 137 that arrives
# much earlier is something else (e.g. the memory limit) and is passed through. The 0.5 s
# slack absorbs start-up and clock granularity. A watcher that was killed before it fired
# (wrc 137) with a command that exited on its own therefore never turns into a timeout.
#
# The wrapper itself writes nothing: its own stderr is /dev/null and the command's stderr
# is fd 3.
RUN_WRAPPER = r"""
exec 3>&2 2>/dev/null
now_cs=0
uptime_cs() {
  local up=0.00 ip fp=00
  read -r up _ </proc/uptime
  ip=${up%%.*}
  if [[ $up == *.* ]]; then
    fp=${up#*.}00
    fp=${fp:0:2}
  fi
  now_cs=$((10#${ip:-0} * 100 + 10#$fp))
}
limit_cs=0
case "$1" in
  ''|*[!0-9]*) ;;
  *) limit_cs=$(($1 * 100 - 50)) ;;
esac
uptime_cs
start_cs=$now_cs
setsid bash -lc "$2" </dev/null 2>&3 3>&- &
child=$!
setsid bash -c 'sleep "$1"; kill -KILL -- "-$2"; exit 0' airlock-watch "$1" "$child" >/dev/null 2>&1 </dev/null 3>&- &
watcher=$!
wait "$child"
rc=$?
uptime_cs
elapsed_cs=$((now_cs - start_cs))
kill -KILL -- "-$child" "$child"
kill -KILL -- "-$watcher" "$watcher"
wait "$watcher"
wrc=$?
if [ "$wrc" -eq 0 ]; then
  exit 124
fi
if [ "$rc" -eq 137 ] && [ "$elapsed_cs" -ge "$limit_cs" ]; then
  exit 124
fi
exit "$rc"
"""

# sh; $@ = pids to keep. Kills every other process using builtins only (no fork per pid).
REAP_SCRIPT = r"""
self=$$
for d in /proc/[0-9]*; do
  pid=${d#/proc/}
  if [ "$pid" = "$self" ]; then
    continue
  fi
  keep=0
  for k in "$@"; do
    if [ "$pid" = "$k" ]; then
      keep=1
    fi
  done
  if [ "$keep" = 1 ]; then
    continue
  fi
  kill -KILL "$pid" 2>/dev/null
done
exit 0
"""

# sh; $1 = absolute target path; content on stdin. Silent on success, non-zero on failure.
WRITE_SCRIPT = r"""
set -e
dir=${1%/*}
if [ -n "$dir" ]; then
  mkdir -p "$dir"
fi
cat > "$1"
"""

# sh; no args. Prints "memory_bytes N", "pids N", "cpu_ns N" for each readable source.
# cgroup v2 files are tried first, then the v1 files.
PEAK_SCRIPT = r"""
emit() {
  if [ -r "$2" ]; then
    if read -r v < "$2"; then
      echo "$1 $v"
    fi
  fi
}
cg=/sys/fs/cgroup
if [ -r "$cg/memory.current" ]; then
  emit memory_bytes "$cg/memory.current"
else
  emit memory_bytes "$cg/memory/memory.usage_in_bytes"
fi
if [ -r "$cg/pids.current" ]; then
  emit pids "$cg/pids.current"
else
  emit pids "$cg/pids/pids.current"
fi
if [ -r "$cg/cpu.stat" ]; then
  while read -r k v; do
    if [ "$k" = usage_usec ]; then
      echo "cpu_ns $((v * 1000))"
    fi
  done < "$cg/cpu.stat"
else
  emit cpu_ns "$cg/cpuacct/cpuacct.usage"
fi
exit 0
"""
