#!/usr/bin/env bash
# Run README demo smoke tests directly on VM.
#
# Usage:
#   ./tests/selftests.sh [-t case1,case2] [-s case3,case4] [-l] [-v] [./src/nettrace-x86] [/tmp/nettrace-selftest]

set -euo pipefail

usage() {
	echo "Usage: $0 [-t case1,case2] [-s case3,case4] [-l] [-v] [BIN] [OUT]"
}

TEST_ITEMS=""
SKIP_ITEMS=""
LIST_ONLY=0
VERBOSE=0
while getopts ":t:s:lvh" opt; do
	case "$opt" in
	t)
		TEST_ITEMS="$OPTARG"
		;;
	s)
		SKIP_ITEMS="$OPTARG"
		;;
	l)
		LIST_ONLY=1
		;;
	v)
		VERBOSE=1
		;;
	h)
		usage
		exit 0
		;;
	\?)
		echo "invalid option: -$OPTARG" >&2
		usage >&2
		exit 2
		;;
	:)
		echo "option -$OPTARG requires an argument" >&2
		usage >&2
		exit 2
		;;
	esac
done
shift $((OPTIND - 1))

BIN="${1:-./src/nettrace}"
OUT="${2:-/tmp/nettrace-selftest}"
mkdir -p "$OUT"

pass=0
fail=0
xfail=0
soft=0
skip=0
ran=0
failed_cmds=""
ns_icmp_diag_rule_added=0
ns_tcp_diag_rule_added=0
ns_env_ready=0

RUN_ID="${RUN_ID:-$$}"
NS0="ntn0_${RUN_ID}"
NS1="ntn1_${RUN_ID}"
V0="ntv0_${RUN_ID}"
V1="ntv1_${RUN_ID}"
NS0_IP="192.168.188.1"
NS1_IP="192.168.188.2"
NS_TCP_PORT=9999
NS_DROP_PORT=8999
NS_HOOK_PORT=18999
NS_LAT_RX_PORT=19001
NS_LAT_TX_PORT=19002
TRACE_MATCHER_RX=""
DEFAULT_FORBID_RE="ERROR: trace not found:|ERROR: entry for exit not found"

declare -A selected=()
declare -A skipped=()
declare -A matched=()

READY_MARKER="begin trace"
READY_POLL_INTERVAL=0.1

normalize_case_name() {
	case "$1" in
	basic_icmp) echo "icmp_lifecycle_basic" ;;
	detail_icmp) echo "icmp_lifecycle_detail" ;;
	trace_stack_icmp) echo "icmp_trace_stack" ;;
	trace_matcher_tcp) echo "tcp_trace_matcher" ;;
	tiny_show) echo "tcp_tiny_show" ;;
	diag_quiet_tcp) echo "tcp_diag_quiet" ;;
	diag_hooks_drop) echo "icmp_diag_hooks" ;;
	drop_mode) echo "tcp_drop_mode" ;;
	sock_mode) echo "tcp_sock_mode" ;;
	latency_show) echo "icmp_latency_show" ;;
	monitor_mode) echo "tcp_monitor_mode" ;;
	rtt_detail) echo "tcp_rtt_detail" ;;
	ns_icmp_addr) echo "icmp_addr_filter" ;;
	ns_icmp_saddr) echo "icmp_saddr_filter" ;;
	ns_tcp_dport) echo "tcp_dport_filter" ;;
	ns_monitor_drop) echo "tcp_monitor_drop" ;;
	ns_diag_hooks_drop) echo "tcp_diag_hooks_drop" ;;
	tcp_latency_recv) echo "tcp_latency_rx" ;;
	tcp_latency_send) echo "tcp_latency_tx" ;;
	*) echo "$1" ;;
	esac
}

ALL_CASES=(
	"icmp_lifecycle_basic"
	"icmp_lifecycle_detail"
	"icmp_trace_stack"
	"tcp_trace_matcher"
	"tcp_tiny_show"
	"tcp_diag_quiet"
	"tcp_drop_mode"
	"tcp_sock_mode"
	"icmp_latency_show"
	"tcp_monitor_mode"
	"tcp_rtt_detail"
	"icmp_diag_hooks"
	"icmp_addr_filter"
	"icmp_saddr_filter"
	"tcp_dport_filter"
	"tcp_monitor_drop"
	"tcp_latency_rx"
	"tcp_latency_tx"
	"tcp_diag_hooks_drop"
)

list_cases() {
	local name

	for name in "${ALL_CASES[@]}"; do
		echo "$name"
	done
}

if [ "$LIST_ONLY" -eq 1 ]; then
	list_cases
	exit 0
fi

if [ -n "$TEST_ITEMS" ]; then
	IFS=',' read -r -a __items <<< "$TEST_ITEMS"
	for item in "${__items[@]}"; do
		local_name=""
		item="${item#"${item%%[![:space:]]*}"}"
		item="${item%"${item##*[![:space:]]}"}"
		[ -z "$item" ] && continue
		local_name="$(normalize_case_name "$item")"
		selected["$local_name"]=1
	done
fi
if [ -n "$SKIP_ITEMS" ]; then
	IFS=',' read -r -a __items <<< "$SKIP_ITEMS"
	for item in "${__items[@]}"; do
		local_name=""
		item="${item#"${item%%[![:space:]]*}"}"
		item="${item%"${item##*[![:space:]]}"}"
		[ -z "$item" ] && continue
		local_name="$(normalize_case_name "$item")"
		skipped["$local_name"]=1
	done
fi

should_run_case() {
	local name="$1"

	[ -n "${skipped[$name]:-}" ] && return 1
	[ "${#selected[@]}" -eq 0 ] && return 0
	[ -n "${selected[$name]:-}" ]
}

wait_for_ready() {
	local log="$1"
	local pid="$2"

	while kill -0 "$pid" 2>/dev/null; do
		if [ -f "$log" ] && grep -q "$READY_MARKER" "$log"; then
			return 0
		fi
		sleep "$READY_POLL_INTERVAL"
	done
	return 1
}

detect_trace_matcher_rx() {
	local probe_log="$OUT/.probe_trace_matcher.log"
	local candidate
	local candidates=(
		"netif_receive_skb"
		"__netif_receive_skb_core"
		"enqueue_to_backlog"
	)

	if ! should_run_case "tcp_trace_matcher"; then
		return 0
	fi

	for candidate in "${candidates[@]}"; do
		timeout 5 "$BIN" --trace-matcher "$candidate" \
			-p tcp --port 1 --tcp-flags S -c 1 --debug \
			>"$probe_log" 2>&1 || true

		if grep -Eq "trace not found: $candidate|trace name=$candidate, .*invalid for: not found" "$probe_log"; then
			continue
		fi

		TRACE_MATCHER_RX="$candidate"
		return 0
	done

	TRACE_MATCHER_RX=""
	return 1
}

needs_ns_env() {
	local names=(
		"icmp_diag_hooks"
		"icmp_addr_filter"
		"icmp_saddr_filter"
		"tcp_dport_filter"
		"tcp_monitor_drop"
		"tcp_diag_hooks_drop"
		"tcp_latency_rx"
		"tcp_latency_tx"
	)
	local name

	for name in "${names[@]}"; do
		if should_run_case "$name"; then
			return 0
		fi
	done
	return 1
}

cleanup_ns_env() {
	ip netns del "$NS0" 2>/dev/null || true
	ip netns del "$NS1" 2>/dev/null || true
	ns_env_ready=0
}

setup_ns_env() {
	cleanup_ns_env

	ip netns add "$NS0"
	ip netns add "$NS1"
	ip link add dev "$V0" type veth peer name "$V1"
	ip link set "$V0" netns "$NS0"
	ip link set "$V1" netns "$NS1"
	ip -n "$NS0" link set lo up
	ip -n "$NS1" link set lo up
	ip -n "$NS0" link set "$V0" up
	ip -n "$NS1" link set "$V1" up
	ip -n "$NS0" addr add "$NS0_IP/24" dev "$V0"
	ip -n "$NS1" addr add "$NS1_IP/24" dev "$V1"

	ns_env_ready=1
}

cleanup_all() {
	if [ "$ns_icmp_diag_rule_added" -eq 1 ]; then
		ip netns exec "$NS1" iptables -D INPUT -p icmp --icmp-type echo-request \
			-s "$NS0_IP" -d "$NS1_IP" -j DROP || true
		ns_icmp_diag_rule_added=0
	fi

	if [ "$ns_tcp_diag_rule_added" -eq 1 ]; then
		ip netns exec "$NS1" iptables -D INPUT -p tcp --dport "$NS_HOOK_PORT" \
			-s "$NS0_IP" -d "$NS1_IP" -j DROP || true
		ns_tcp_diag_rule_added=0
	fi

	if [ "$ns_env_ready" -eq 1 ]; then
		cleanup_ns_env
	fi
}

trap cleanup_all EXIT

skip_case() {
	local name="$1"
	local reason="$2"
	local log="$OUT/$name.log"

	if ! should_run_case "$name"; then
		skip=$((skip + 1))
		printf "%-24s %-6s rc=%-4s log:%s\n" "$name" "SKIP" "-" "$log"
		return 0
	fi

	matched["$name"]=1
	skip=$((skip + 1))
	printf "%-24s %-6s rc=%-4s log:%s\n" "$name" "SKIP" "-" "$log"
	printf "%s\n" "$reason" >"$log"
}

EXPECT_MISSING=""

check_expect() {
	local log="$1"
	local expect_re="$2"
	local expect_mode="${3:-any}"
	local line
	local missing=""

	EXPECT_MISSING=""

	case "$expect_mode" in
	any)
		if grep -Eq "$expect_re" "$log"; then
			return 0
		fi
		EXPECT_MISSING="$expect_re"
		return 1
		;;
	all)
		while IFS= read -r line; do
			local kind="re"
			local pat="$line"

			[ -z "$line" ] && continue

			if [[ "$line" == eq:* ]]; then
				kind="eq"
				pat="${line#eq:}"
			elif [[ "$line" == re:* ]]; then
				kind="re"
				pat="${line#re:}"
			fi

			if [ "$kind" = "eq" ]; then
				if ! grep -Fqx -- "$pat" "$log"; then
					missing+="${line}; "
				fi
			elif ! grep -Eq -- "$pat" "$log"; then
				missing+="${line}; "
			fi
		done <<< "$expect_re"
		;;
	exact)
		while IFS= read -r line; do
			[ -z "$line" ] && continue
			if ! grep -Fqx -- "$line" "$log"; then
				missing+="${line}; "
			fi
		done <<< "$expect_re"
		;;
	*)
		EXPECT_MISSING="invalid expect_mode: $expect_mode"
		return 1
		;;
	esac

	if [ -z "$missing" ]; then
		return 0
	fi

	EXPECT_MISSING="${missing%"; "}"
	return 1
}

STRICT_MISSING=""
STRICT_BAD_LINES=""
STRICT_IGNORE_RE='__kfree_skb|skb_clone'
POST_MISSING=""
POST_BAD_LINES=""

escape_ip_re() {
	printf '%s' "$1" | sed 's/\./\\./g'
}

allow_icmp_pair_re() {
	local saddr
	local daddr

	saddr="$(escape_ip_re "$1")"
	daddr="$(escape_ip_re "$2")"
	printf 'ICMP: %s -> %s' "$saddr" "$daddr"
}

allow_icmp_saddr_re() {
	local saddr

	saddr="$(escape_ip_re "$1")"
	printf 'ICMP: %s ->' "$saddr"
}

allow_icmp_addr_re() {
	local addr

	addr="$(escape_ip_re "$1")"
	printf 'ICMP: %s ->|ICMP: .* -> %s' "$addr" "$addr"
}

allow_tcp_port_re() {
	local port="$1"

	printf 'TCP: .*:%s ->|TCP: .* -> .*:%s' "$port" "$port"
}

allow_tcp_dport_re() {
	local port="$1"

	printf 'TCP: .* -> .*:%s' "$port"
}

run_case_icmp_pair() {
	local saddr="$1"
	local daddr="$2"
	shift 2

	run_case_with_strict "$(allow_icmp_pair_re "$saddr" "$daddr")" "icmp $saddr->$daddr" "$@"
}

run_case_icmp_saddr() {
	local saddr="$1"
	shift 1

	run_case_with_strict "$(allow_icmp_saddr_re "$saddr")" "icmp saddr $saddr" "$@"
}

run_case_icmp_addr() {
	local addr="$1"
	shift 1

	run_case_with_strict "$(allow_icmp_addr_re "$addr")" "icmp addr $addr" "$@"
}

run_case_tcp_port() {
	local port="$1"
	shift 1

	run_case_with_strict "$(allow_tcp_port_re "$port")" "tcp port $port" "$@"
}

run_case_tcp_dport() {
	local port="$1"
	shift 1

	run_case_with_strict "$(allow_tcp_dport_re "$port")" "tcp dport $port" "$@"
}

run_case_with_strict() {
	local strict_re="$1"
	local strict_desc="$2"
	shift 2
	local base=("${@:1:8}")
	local extra=("${@:9}")

	run_case "${base[@]}" "$strict_re" "$strict_desc" "${extra[@]}"
}

check_filtered_traces() {
	local log="$1"
	local allow_re="$2"
	local desc="${3:-filtered trace}"
	local trace_re='(TCP|UDP|ICMP|ARP):|ether protocol:|unknow'
	local lines
	local bad

	STRICT_MISSING=""
	STRICT_BAD_LINES=""

	[ -z "$allow_re" ] && return 0

	lines="$(grep -E "$trace_re" "$log" || true)"
	[ -z "$lines" ] && return 0

	bad="$(printf '%s\n' "$lines" | grep -E -v -- "$allow_re" | grep -E -v -- "$STRICT_IGNORE_RE" || true)"
	if [ -n "$bad" ]; then
		STRICT_MISSING="$desc"
		STRICT_BAD_LINES="$bad"
		{
			echo "ERROR: unexpected trace record(s) for filter: $desc"
			printf '%s\n' "$bad"
		} >> "$log"
		return 1
	fi

	return 0
}

check_tiny_show() {
	local log="$1"
	local proto_re="${2:-TCP:}"
	local out
	local rc

	POST_MISSING=""
	POST_BAD_LINES=""

	out="$(awk -v proto_re="$proto_re" '
		BEGIN { bad=0; in_block=0; first=0; }
		/^\*{5}/ { in_block=1; first=1; next }
		/^end trace\.\.\./ { in_block=0; next }
		/^\[/ {
			if (!in_block)
				next
			if (first) {
				if ($0 !~ proto_re) {
					print "first line missing packet info: " $0
					bad=1
				}
				first=0
			} else if ($0 ~ proto_re) {
				print "unexpected packet info: " $0
				bad=1
			}
		}
		END { exit bad }
	' "$log")"
	rc=$?
	if [ "$rc" -ne 0 ]; then
		POST_MISSING="tiny-show only first line has packet info"
		POST_BAD_LINES="$out"
		{
			echo "ERROR: tiny-show should only show packet info on the first function line of each block"
			[ -n "$out" ] && printf '%s\n' "$out"
		} >> "$log"
		return 1
	fi

	return 0
}

run_case() {
	local name="$1"
	local cmd="$2"
	local trigger="$3"
	local expect_re="$4"
	local mode="${5:-pass}"
	local xfail_re="${6:-}"
	local forbid_re="${7:-}"
	local expect_mode="${8:-any}"
	local strict_re="${9:-}"
	local strict_desc="${10:-}"
	local post_check="${11:-}"
	local post_arg="${12:-}"
	local combined_forbid_re="$DEFAULT_FORBID_RE"
	local log="$OUT/$name.log"
	local trig_log="$OUT/$name.trigger.log"
	local rc
	local result="FAIL"
	local strict_ok=1
	local post_ok=1

	if ! should_run_case "$name"; then
		skip=$((skip + 1))
		printf "%-24s %-6s rc=%-4s log:%s\n" "$name" "SKIP" "-" "$log"
		return 0
	fi

	matched["$name"]=1
	ran=$((ran + 1))

	rm -f "$log" "$trig_log"

	set +e
	if [ "$VERBOSE" -eq 1 ]; then
		printf -- "----- [%s] begin -----\n" "$name"
		(eval "timeout 20 $BIN $cmd 2>&1 | tee \"$log\"") &
	else
		(eval "timeout 20 $BIN $cmd >\"$log\" 2>&1") &
	fi
	local pid=$!
	if [ -n "$trigger" ]; then
		wait_for_ready "$log" "$pid"
		if [ "$VERBOSE" -eq 1 ]; then
			bash -lc "$trigger" 2>&1 | tee "$trig_log"
		else
			bash -lc "$trigger" >"$trig_log" 2>&1
		fi
	fi
	wait "$pid"
	rc=$?
	if [ "$VERBOSE" -eq 1 ]; then
		printf -- "----- [%s] end (rc=%s) -----\n" "$name" "$rc"
	fi
	set -e

	if [ -n "$strict_re" ]; then
		if ! check_filtered_traces "$log" "$strict_re" "${strict_desc:-$strict_re}"; then
			strict_ok=0
		fi
	fi
	if [ -n "$post_check" ]; then
		if ! "$post_check" "$log" "$post_arg"; then
			post_ok=0
		fi
	fi

	if [ "$mode" = "xfail" ]; then
		if grep -Eq "$xfail_re" "$log"; then
			result="XFAIL"
			xfail=$((xfail + 1))
		else
			result="FAIL"
			fail=$((fail + 1))
		fi
	elif [ "$mode" = "soft" ]; then
		if [ -n "$forbid_re" ]; then
			combined_forbid_re="${combined_forbid_re}|${forbid_re}"
		fi

		if grep -Eq "$combined_forbid_re" "$log"; then
			result="SOFTFAIL"
			soft=$((soft + 1))
		elif ! check_expect "$log" "$expect_re" "$expect_mode"; then
			result="SOFTFAIL"
			soft=$((soft + 1))
		elif [ "$strict_ok" -eq 0 ]; then
			result="SOFTFAIL"
			soft=$((soft + 1))
		elif [ "$post_ok" -eq 0 ]; then
			result="SOFTFAIL"
			soft=$((soft + 1))
		else
			result="PASS"
			pass=$((pass + 1))
		fi
	else
		if [ -n "$forbid_re" ]; then
			combined_forbid_re="${combined_forbid_re}|${forbid_re}"
		fi

		if grep -Eq "$combined_forbid_re" "$log"; then
			result="FAIL"
			fail=$((fail + 1))
			failed_cmds+=$'\n'"[$name] timeout 20 $BIN $cmd"$'\n'"  trigger: $trigger"$'\n'"  forbidden_re: $combined_forbid_re"$'\n'
		elif ! check_expect "$log" "$expect_re" "$expect_mode"; then
			result="FAIL"
			fail=$((fail + 1))
			failed_cmds+=$'\n'"[$name] timeout 20 $BIN $cmd"$'\n'"  trigger: $trigger"$'\n'"  expect_mode: $expect_mode"$'\n'"  missing: $EXPECT_MISSING"$'\n'
		elif [ "$strict_ok" -eq 0 ]; then
			result="FAIL"
			fail=$((fail + 1))
			failed_cmds+=$'\n'"[$name] timeout 20 $BIN $cmd"$'\n'"  trigger: $trigger"$'\n'"  strict_filter: ${STRICT_MISSING:-unexpected trace record}"$'\n'
		elif [ "$post_ok" -eq 0 ]; then
			result="FAIL"
			fail=$((fail + 1))
			failed_cmds+=$'\n'"[$name] timeout 20 $BIN $cmd"$'\n'"  trigger: $trigger"$'\n'"  post_check: ${POST_MISSING:-$post_check}"$'\n'
		else
			result="PASS"
			pass=$((pass + 1))
		fi
	fi

	printf "%-24s %-6s rc=%-4s log:%s\n" "$name" "$result" "$rc" "$log"
}

# 3.1.1 basic trace
run_case_icmp_pair 127.0.0.1 127.0.0.1 \
	"icmp_lifecycle_basic" \
	"-p icmp --saddr 127.0.0.1 --daddr 127.0.0.1 -c 4" \
	"for i in \$(seq 1 8); do ping -c 1 -W 1 127.0.0.1 || true; sleep 0.15; done" \
	$'eq:begin trace...\nre:ICMP: 127\\.0\\.0\\.1 -> 127\\.0\\.0\\.1\neq:end trace...' \
	"pass" \
	"" \
	"" \
	"all"

# 3.1.2 detail output
run_case_icmp_pair 127.0.0.1 127.0.0.1 \
	"icmp_lifecycle_detail" \
	"-p icmp --saddr 127.0.0.1 --daddr 127.0.0.1 --detail -c 4" \
	"for i in \$(seq 1 8); do ping -c 1 -W 1 127.0.0.1 || true; sleep 0.15; done" \
	$'eq:begin trace...\nre:\\[cpu:\nre:\\[ns:\neq:end trace...' \
	"pass" \
	"" \
	"" \
	"all"

# 3.1.4 call stack
run_case_icmp_pair 127.0.0.1 127.0.0.1 \
	"icmp_trace_stack" \
	"-p icmp --saddr 127.0.0.1 --daddr 127.0.0.1 --trace-stack consume_skb,icmp_rcv -c 4" \
	"for i in \$(seq 1 8); do ping -c 1 -W 1 127.0.0.1 || true; sleep 0.15; done" \
	$'eq:Call Stack:\nre:-> \\[\neq:end trace...' \
	"pass" \
	"" \
	"rust_binder" \
	"all"

# 3.1.5 trace matcher/exclude
if detect_trace_matcher_rx; then
	run_case_tcp_port 12345 \
		"tcp_trace_matcher" \
		"--trace-matcher $TRACE_MATCHER_RX --trace-exclude napi_gro_receive_entry,dev_gro_receive -p tcp --port 12345 --tcp-flags S -c 4" \
		"for i in \$(seq 1 8); do echo hi | nc -w 1 127.0.0.1 12345 || true; sleep 0.15; done" \
		$'eq:begin trace...\nre:TCP:\nre:\\['"$TRACE_MATCHER_RX"$'[[:space:]]*\\]\neq:end trace...' \
		"pass" \
		"" \
		"napi_gro_receive_entry|dev_gro_receive" \
		"all"
else
	skip_case \
		"tcp_trace_matcher" \
		"no available trace-matcher candidate in current kernel: netif_receive_skb,__netif_receive_skb_core,enqueue_to_backlog"
fi

# 3.1.6 tiny-show
run_case_tcp_port 9999 \
	"tcp_tiny_show" \
	"--tiny-show -p tcp --port 9999 -c 10" \
	"for i in \$(seq 1 8); do echo hi | nc -w 1 127.0.0.1 9999 || true; sleep 0.15; done" \
	$'eq:begin trace...\nre:TCP:\neq:end trace...' \
	"pass" \
	"" \
	"" \
	"all" \
	"check_tiny_show"

# 3.2.3 diag quiet
run_case_tcp_port 9999 \
	"tcp_diag_quiet" \
	"--diag --diag-quiet -p tcp --port 9999" \
	"for i in \$(seq 1 10); do echo hi | nc -w 1 127.0.0.1 9999 || true; sleep 0.12; done" \
	$'eq:---------------- ANALYSIS RESULT ---------------------\nre:tcp port is not listened|packet is dropped\neq:analysis finished!' \
	"pass" \
	"" \
	"" \
	"all"

# 3.3 drop monitor
run_case \
	"tcp_drop_mode" \
	"--drop" \
	"for i in \$(seq 1 8); do echo hi | nc -w 1 127.0.0.1 9999 || true; sleep 0.12; done" \
	$'re:TCP:\nre:reason: NO_SOCKET' \
	"pass" \
	"" \
	"" \
	"all"

# 3.4 sock mode
run_case_tcp_port 10000 \
	"tcp_sock_mode" \
	"-p tcp --port 10000 --sock -c 10" \
	"timeout 5 nc -l 127.0.0.1 10000 & s=\$!; sleep 0.3; echo hi | nc -w 1 127.0.0.1 10000 || true; wait \$s || true" \
	$'eq:begin trace...\nre:__tcp_transmit_skb\nre:TCP: 127\\.0\\.0\\.1:.* -> 127\\.0\\.0\\.1:10000\neq:end trace...' \
	"pass" \
	"" \
	"" \
	"all"

# 3.6.1 latency show
run_case_icmp_pair 127.0.0.1 127.0.0.1 \
	"icmp_latency_show" \
	"-p icmp --saddr 127.0.0.1 --daddr 127.0.0.1 --latency-show -c 4" \
	"for i in \$(seq 1 8); do ping -c 1 -W 1 127.0.0.1 || true; sleep 0.15; done" \
	$'re:latency:\nre:total latency' \
	"pass" \
	"" \
	"" \
	"all"

# 3.5 monitor mode (kernel feature dependent)
run_case_tcp_port 9999 \
	"tcp_monitor_mode" \
	"--monitor -p tcp --port 9999 -c 20" \
	"for i in \$(seq 1 30); do echo hi | nc -w 1 127.0.0.1 9999 || true; sleep 0.05; done" \
	$'eq:begin trace...\nre:TCP:\nre:reason: NO_SOCKET\neq:end trace...' \
	"pass" \
	"" \
	"" \
	"all"

# 3.6.2 rtt detail
run_case \
	"tcp_rtt_detail" \
	"--sock -t tcp_ack_update_rtt --filter-srtt 0 -c 4" \
	"timeout 6 iperf3 -s -1 -p 5201 & sleep 0.6; timeout 4 iperf3 -c 127.0.0.1 -p 5201 -t 1 || true" \
	$'re:tcp_ack_update_rtt\nre:srtt:|rtt:' \
	"soft" \
	"" \
	"" \
	"all"

# 3.7 namespace + veth scenarios
if needs_ns_env; then
	setup_ns_env
fi

# 3.2.2 hooks (icmp + netfilter), rule is scoped to test src/dst in namespace only
if should_run_case "icmp_diag_hooks"; then
	ip netns exec "$NS1" iptables -I INPUT 1 -p icmp --icmp-type echo-request \
		-s "$NS0_IP" -d "$NS1_IP" -j DROP
	ns_icmp_diag_rule_added=1
fi
run_case_icmp_pair "$NS0_IP" "$NS1_IP" \
	"icmp_diag_hooks" \
	"--diag --hooks -p icmp --saddr $NS0_IP --daddr $NS1_IP -c 2" \
	"for i in \$(seq 1 8); do ip netns exec $NS0 ping -c 1 -W 1 $NS1_IP || true; sleep 0.12; done" \
	$'eq:---------------- ANALYSIS RESULT ---------------------\nre:following hook functions are blamed\nre:packet is dropped by netfilter\neq:analysis finished!\neq:end trace...' \
	"pass" \
	"" \
	"" \
	"all"
if [ "$ns_icmp_diag_rule_added" -eq 1 ]; then
	ip netns exec "$NS1" iptables -D INPUT -p icmp --icmp-type echo-request \
		-s "$NS0_IP" -d "$NS1_IP" -j DROP || true
	ns_icmp_diag_rule_added=0
fi

run_case_icmp_addr "$NS1_IP" \
	"icmp_addr_filter" \
	"-p icmp --addr $NS1_IP -c 4" \
	"for i in \$(seq 1 8); do ip netns exec $NS0 ping -c 1 -W 1 $NS1_IP || true; sleep 0.12; done" \
	$'eq:begin trace...\nre:ICMP: '"$NS0_IP"' -> '"$NS1_IP"$'\neq:end trace...' \
	"pass" \
	"" \
	"" \
	"all"

run_case_icmp_saddr "$NS0_IP" \
	"icmp_saddr_filter" \
	"-p icmp --saddr $NS0_IP -c 4" \
	"for i in \$(seq 1 8); do ip netns exec $NS0 ping -c 1 -W 1 $NS1_IP || true; sleep 0.12; done" \
	$'eq:begin trace...\nre:ICMP: '"$NS0_IP"' -> '"$NS1_IP"$'\neq:end trace...' \
	"pass" \
	"" \
	"" \
	"all"

run_case_tcp_dport "$NS_TCP_PORT" \
	"tcp_dport_filter" \
	"--basic -p tcp --dport $NS_TCP_PORT -c 4" \
	"timeout 5 ip netns exec $NS1 nc -l -p $NS_TCP_PORT & s=\$!; sleep 0.3; echo hi | ip netns exec $NS0 nc -w 1 $NS1_IP $NS_TCP_PORT || true; wait \$s || true" \
	$'eq:begin trace...\nre:TCP: '"$NS0_IP"$':.* -> '"$NS1_IP:$NS_TCP_PORT"$'\neq:end trace...' \
	"pass" \
	"" \
	"" \
	"all"

run_case_tcp_dport "$NS_DROP_PORT" \
	"tcp_monitor_drop" \
	"--monitor -p tcp --dport $NS_DROP_PORT -c 20" \
	"for i in \$(seq 1 30); do echo hi | ip netns exec $NS0 nc -w 1 $NS1_IP $NS_DROP_PORT || true; sleep 0.05; done" \
	$'eq:begin trace...\nre:TCP: '"$NS0_IP"$':.* -> '"$NS1_IP:$NS_DROP_PORT"$'\nre:kfree_skb\nre:reason: NO_SOCKET\neq:end trace...' \
	"pass" \
	"" \
	"" \
	"all"

# 3.7.1 TCP latency (RX path), based on README 3.6.1 receive-stage example
run_case_tcp_port "$NS_LAT_RX_PORT" \
	"tcp_latency_rx" \
	"--latency -p tcp --port $NS_LAT_RX_PORT -t tcp_queue_rcv,tcp_data_queue_ofo --trace-matcher tcp_queue_rcv,tcp_data_queue_ofo --latency-free --min-latency 0 -c 4" \
	"timeout 8 ip netns exec $NS1 nc -l -p $NS_LAT_RX_PORT & s=\$!; sleep 0.3; dd if=/dev/zero bs=1024 count=128 2>/dev/null | ip netns exec $NS0 nc -w 2 $NS1_IP $NS_LAT_RX_PORT || true; wait \$s || true" \
	$'eq:begin trace...\nre:TCP: '"$NS0_IP"$':.* -> '"$NS1_IP:$NS_LAT_RX_PORT"$'.*latency:\nre:tcp_queue_rcv|tcp_data_queue_ofo\neq:end trace...' \
	"pass" \
	"" \
	"" \
	"all"

# 3.7.2 TCP latency (TX path), based on README 3.6.1 send-stage example
run_case_tcp_port "$NS_LAT_TX_PORT" \
	"tcp_latency_tx" \
	"--latency -p tcp --port $NS_LAT_TX_PORT -t __ip_queue_xmit,dev_hard_start_xmit --trace-matcher __ip_queue_xmit --trace-free dev_hard_start_xmit --min-latency 0 -c 4" \
	"timeout 8 ip netns exec $NS1 nc -l -p $NS_LAT_TX_PORT & s=\$!; sleep 0.3; dd if=/dev/zero bs=1024 count=128 2>/dev/null | ip netns exec $NS0 nc -w 2 $NS1_IP $NS_LAT_TX_PORT || true; wait \$s || true" \
	$'eq:begin trace...\nre:TCP: '"$NS0_IP"$':.* -> '"$NS1_IP:$NS_LAT_TX_PORT"$'.*latency:\nre:__ip_queue_xmit|dev_hard_start_xmit\neq:end trace...' \
	"pass" \
	"" \
	"" \
	"all"

if should_run_case "tcp_diag_hooks_drop"; then
	ip netns exec "$NS1" iptables -I INPUT 1 -p tcp --dport "$NS_HOOK_PORT" \
		-s "$NS0_IP" -d "$NS1_IP" -j DROP
	ns_tcp_diag_rule_added=1
fi
run_case_tcp_dport "$NS_HOOK_PORT" \
	"tcp_diag_hooks_drop" \
	"--diag --hooks -p tcp --dport $NS_HOOK_PORT" \
	"for i in \$(seq 1 8); do echo hi | ip netns exec $NS0 nc -w 1 $NS1_IP $NS_HOOK_PORT || true; sleep 0.12; done" \
	$'eq:---------------- ANALYSIS RESULT ---------------------\nre:packet is dropped by netfilter\nre:following hook functions are blamed\neq:analysis finished!\neq:end trace...' \
	"pass" \
	"" \
	"" \
	"all"
if [ "$ns_tcp_diag_rule_added" -eq 1 ]; then
	ip netns exec "$NS1" iptables -D INPUT -p tcp --dport "$NS_HOOK_PORT" \
		-s "$NS0_IP" -d "$NS1_IP" -j DROP || true
	ns_tcp_diag_rule_added=0
fi

if [ "${#selected[@]}" -ne 0 ]; then
	unknown=""
	for name in "${!selected[@]}"; do
		if [ -z "${matched[$name]:-}" ]; then
			unknown+="${name},"
		fi
	done
	if [ -n "$unknown" ]; then
		unknown="${unknown%,}"
		echo "WARN: unknown test item(s): $unknown" >&2
	fi
fi

echo
echo "SUMMARY: pass=$pass xfail=$xfail softfail=$soft fail=$fail skip=$skip ran=$ran logs=$OUT"
if [ "$fail" -ne 0 ]; then
	echo "FAILED COMMANDS:"
	printf "%s" "$failed_cmds"
fi
if [ "$fail" -ne 0 ]; then
	exit 1
fi
